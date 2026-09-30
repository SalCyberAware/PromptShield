"""A judge reply cut off mid-JSON is an analyzer error, never a verdict.

gemini-3.6-flash spent 289 of its 300 output tokens thinking on BM-0148 and
stopped four tokens into the JSON. Replies like that must come back as the 0.0
"produced nothing" sentinel, so the case is reported unjudged or handed to the
next judge. They must never be read as a verdict: a half-written
``"verdict": "failed"`` scored as a held attack is exactly the failure this
guards against.

Also pins the output budgets that stop it happening: 1024 for every judge that
takes one, and no thinking for Gemini.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptshield.analyzers import gemini_analyzer, ollama_analyzer, openai_analyzer
from promptshield.analyzers.gemini_analyzer import GeminiAnalyzer
from promptshield.analyzers.ollama_analyzer import OllamaAnalyzer
from promptshield.analyzers.openai_analyzer import OpenAIAnalyzer
from promptshield.analyzers.verdict_json import read_reply
from promptshield.models import Attack

#: Real shapes from the four BM-0073/-0077/-0097/-0148 failures.
CUT_OFF = [
    '{"verdict": "failed", "confidence":',
    '{   "verdict": "uncertain',
    '{   "verdict": "',
    '{"verdict": "success", "confidence": 0.9, "reasoning": "The target produced',
]


@pytest.mark.parametrize("reply", CUT_OFF)
def test_the_parser_finds_no_verdict_in_a_cut_off_reply(reply: str) -> None:
    assert read_reply(reply) is None


class TestGemini:
    @staticmethod
    def _reply(text: str, finish: str = "MAX_TOKENS") -> MagicMock:
        reply = MagicMock()
        reply.text = text
        candidate = MagicMock()
        candidate.finish_reason.name = finish
        reply.candidates = [candidate]
        return reply

    async def _analyze(self, attack: Attack, reply: MagicMock) -> tuple[object, AsyncMock]:
        analyzer = GeminiAnalyzer(api_key="g-test")
        analyzer._client = MagicMock()
        create = AsyncMock(return_value=reply)
        analyzer._client.aio.models.generate_content = create
        with patch("promptshield.analyzers.gemini_analyzer.asyncio.sleep", AsyncMock()):
            verdict = await analyzer.analyze(attack, "a response")
        return verdict, create

    @pytest.mark.parametrize("text", CUT_OFF)
    async def test_a_cut_off_reply_is_an_analyzer_error(
        self, sample_attack_llm01: Attack, text: str
    ) -> None:
        verdict, _ = await self._analyze(sample_attack_llm01, self._reply(text))
        assert verdict.confidence_score == 0.0  # type: ignore[attr-defined]
        assert "finish reason MAX_TOKENS" in (verdict.reasoning or "")  # type: ignore[attr-defined]

    async def test_the_call_asks_for_json_1024_tokens_and_no_thinking(
        self, sample_attack_llm01: Attack
    ) -> None:
        complete = '{"verdict": "failed", "confidence": 0.9, "reasoning": "refused"}'
        verdict, create = await self._analyze(
            sample_attack_llm01, self._reply(complete, finish="STOP")
        )
        config = create.await_args.kwargs["config"]
        assert config.response_mime_type == "application/json"
        assert config.max_output_tokens == gemini_analyzer.MAX_OUTPUT_TOKENS == 1024
        assert config.thinking_config.thinking_budget == 0
        assert verdict.confidence_score == 0.9  # type: ignore[attr-defined]


class TestOpenAI:
    async def _analyze(self, attack: Attack, text: str) -> tuple[object, AsyncMock]:
        analyzer = OpenAIAnalyzer(api_key="sk-test-not-real")
        completion = MagicMock()
        choice = MagicMock()
        choice.message.content = text
        completion.choices = [choice]
        create = AsyncMock(return_value=completion)
        with patch.object(analyzer._client.chat.completions, "create", create):
            verdict = await analyzer.analyze(attack, "a response")
        return verdict, create

    @pytest.mark.parametrize("text", CUT_OFF)
    async def test_a_cut_off_reply_is_an_analyzer_error(
        self, sample_attack_llm01: Attack, text: str
    ) -> None:
        verdict, _ = await self._analyze(sample_attack_llm01, text)
        assert verdict.confidence_score == 0.0  # type: ignore[attr-defined]

    async def test_the_output_budget_is_1024(self, sample_attack_llm01: Attack) -> None:
        _, create = await self._analyze(sample_attack_llm01, CUT_OFF[0])
        assert create.await_args.kwargs["max_tokens"] == openai_analyzer.MAX_OUTPUT_TOKENS == 1024


class TestOllama:
    async def _analyze(self, attack: Attack, text: str) -> tuple[object, AsyncMock]:
        analyzer = OllamaAnalyzer()
        response = MagicMock()
        response.message = MagicMock()
        response.message.content = text
        chat = AsyncMock(return_value=response)
        with patch.object(analyzer, "_client", MagicMock(chat=chat)):
            verdict = await analyzer.analyze(attack, "a response")
        return verdict, chat

    @pytest.mark.parametrize("text", CUT_OFF)
    async def test_a_cut_off_reply_is_an_analyzer_error(
        self, sample_attack_llm01: Attack, text: str
    ) -> None:
        verdict, _ = await self._analyze(sample_attack_llm01, text)
        assert verdict.confidence_score == 0.0  # type: ignore[attr-defined]

    async def test_the_output_budget_is_set_explicitly(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Left unset, the limit is whatever the Ollama server defaults to."""
        _, chat = await self._analyze(sample_attack_llm01, CUT_OFF[0])
        assert chat.await_args.kwargs["options"] == {
            "num_predict": ollama_analyzer.MAX_OUTPUT_TOKENS
        }
        assert ollama_analyzer.MAX_OUTPUT_TOKENS == 1024
