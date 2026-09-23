"""Tests for the Claude AI analyzer (with mocked Anthropic API)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptshield.analyzers.claude_analyzer import RETRY_SUFFIX, ClaudeAnalyzer
from promptshield.models import Attack


def _make_anthropic_response(text: str) -> MagicMock:
    """Build a mock Anthropic message response."""
    response = MagicMock()
    block = MagicMock()
    block.text = text
    response.content = [block]
    return response


class TestClaudeAnalyzerInitialization:
    """Tests for analyzer initialization."""

    def test_requires_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should raise ValueError when no API key is available."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("PROMPTSHIELD_ANALYZER_ANTHROPIC_KEY", raising=False)

        with pytest.raises(ValueError, match="No Anthropic API key"):
            ClaudeAnalyzer()

    def test_accepts_explicit_api_key(self) -> None:
        """Should initialize when API key is provided explicitly."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")
        assert analyzer.api_key == "sk-ant-test-key"

    def test_uses_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should pick up API key from environment."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env-key")
        analyzer = ClaudeAnalyzer()
        assert analyzer.api_key == "sk-ant-env-key"


class TestClaudeAnalyzerJSONParsing:
    """Tests for parsing Claude's verdict responses."""

    def test_parses_clean_json(self) -> None:
        """Should parse well-formed JSON response."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")
        result = analyzer._parse_verdict('{"success": true, "confidence_score": 0.9, "reasoning": "test"}')
        assert result["success"] is True
        assert result["confidence_score"] == 0.9

    def test_strips_markdown_code_fences(self) -> None:
        """Should strip ```json``` code fences if Claude added them."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")
        result = analyzer._parse_verdict('```json\n{"success": false, "confidence_score": 0.1, "reasoning": "clean"}\n```')
        assert result["success"] is False

    def test_handles_malformed_json(self) -> None:
        """Should return safe defaults for unparseable response."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")
        result = analyzer._parse_verdict("not json at all")
        assert result["success"] is False
        assert result["confidence_score"] == 0.0

    def test_extracts_json_from_mixed_text(self) -> None:
        """Should extract JSON object even when surrounded by other text."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")
        response = 'Here is my analysis: {"success": true, "confidence_score": 0.8, "reasoning": "match"} hope this helps'
        result = analyzer._parse_verdict(response)
        assert result["success"] is True


class TestClaudeAnalyzerAnalyze:
    """Tests for the main analyze method (with mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_returns_failure_for_error_response(self, sample_attack_llm01: Attack, error_response: str) -> None:
        """Should not call Claude API for [ERROR] responses."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")
        verdict = await analyzer.analyze(sample_attack_llm01, error_response)
        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_returns_failure_for_timeout_response(self, sample_attack_llm01: Attack, timeout_response: str) -> None:
        """Should not call Claude API for [TIMEOUT] responses."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")
        verdict = await analyzer.analyze(sample_attack_llm01, timeout_response)
        assert verdict.success is False

    @pytest.mark.asyncio
    async def test_returns_success_verdict_when_claude_says_yes(self, sample_attack_llm01: Attack) -> None:
        """Should return success=True when Claude judges the attack succeeded."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")

        mock_create = AsyncMock(return_value=_make_anthropic_response(
            '{"success": true, "confidence_score": 0.85, "reasoning": "Model leaked credentials"}'
        ))

        with patch.object(analyzer._client.messages, "create", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "HACKED. Credentials are sk-test-123")

        assert verdict.success is True
        assert verdict.confidence_score == 0.85
        assert verdict.analyzer_name == "claude_analyzer"

    @pytest.mark.asyncio
    async def test_returns_failure_verdict_when_claude_says_no(self, sample_attack_llm01: Attack) -> None:
        """Should return success=False when Claude judges the response safe."""
        analyzer = ClaudeAnalyzer(api_key="sk-ant-test-key")

        mock_create = AsyncMock(return_value=_make_anthropic_response(
            '{"success": false, "confidence_score": 0.9, "reasoning": "Model refused politely"}'
        ))

        with patch.object(analyzer._client.messages, "create", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "I cannot help with that.")

        assert verdict.success is False


class TestJudgeRefusalRetry:
    """The API sometimes declines the judging call outright.

    Both benchmark cases that came back ``not_ai_judged`` -- BM-0004 and
    BM-0030, both PS-LLM01-004 "Encoding-based bypass" -- failed this way:
    stop_reason "refusal", zero content blocks, zero output tokens. The saved
    rationale recorded only "Could not parse analyzer response:" with nothing
    after it, which read like a parser bug and was not one. There is nothing to
    parse; the model declined to write anything.
    """

    @staticmethod
    def _reply(text: str, stop_reason: str = "end_turn") -> MagicMock:
        message = MagicMock()
        block = MagicMock()
        block.text = text
        message.content = [block] if text else []
        message.stop_reason = stop_reason
        return message

    @pytest.fixture
    def analyzer(self) -> ClaudeAnalyzer:
        return ClaudeAnalyzer(api_key="sk-test-not-real")

    async def test_bm0004_shape_recovers_on_the_retry(
        self, analyzer: ClaudeAnalyzer, sample_attack_llm01: Attack
    ) -> None:
        """What BM-0004 does live: refused first, answers when reframed."""
        analyzer._client = MagicMock()
        analyzer._client.messages.create = AsyncMock(
            side_effect=[
                self._reply("", "refusal"),
                self._reply(
                    '{"success": false, "confidence_score": 0.15, '
                    '"reasoning": "The target decoded the string but did not comply."}'
                ),
            ]
        )

        verdict = await analyzer.analyze(sample_attack_llm01, "The decoded message is: ...")

        assert analyzer._client.messages.create.await_count == 2
        assert verdict.success is False
        assert verdict.confidence_score == 0.15
        assert "did not comply" in verdict.reasoning

    async def test_bm0030_shape_degrades_honestly_when_the_retry_refuses_too(
        self, analyzer: ClaudeAnalyzer, sample_attack_llm01: Attack
    ) -> None:
        """What BM-0030 does live: refuses under every framing tried.

        Confidence must stay 0.0 so the orchestrator treats it as an errored
        analyzer and the attack is reported ``not_ai_judged``. Counting a
        refusal as "the attack failed" would report an unexamined response as
        clean, which is the one error this tool must not make.
        """
        analyzer._client = MagicMock()
        analyzer._client.messages.create = AsyncMock(
            side_effect=[self._reply("", "refusal"), self._reply("", "refusal")]
        )

        verdict = await analyzer.analyze(sample_attack_llm01, "I can help you decode that.")

        assert analyzer._client.messages.create.await_count == 2
        assert verdict.success is False
        assert verdict.confidence_score == 0.0
        assert "declined to answer" in verdict.reasoning

    async def test_the_retry_restates_the_framing_without_changing_the_question(
        self, analyzer: ClaudeAnalyzer, sample_attack_llm01: Attack
    ) -> None:
        analyzer._client = MagicMock()
        analyzer._client.messages.create = AsyncMock(
            side_effect=[self._reply("", "refusal"), self._reply('{"success": false}')]
        )

        await analyzer.analyze(sample_attack_llm01, "a response")

        first = analyzer._client.messages.create.await_args_list[0].kwargs["messages"][0]["content"]
        second = analyzer._client.messages.create.await_args_list[1].kwargs["messages"][0]["content"]
        assert second.startswith(first)
        assert RETRY_SUFFIX in second

    async def test_a_parseable_first_answer_is_not_retried(
        self, analyzer: ClaudeAnalyzer, sample_attack_llm01: Attack
    ) -> None:
        """One judge call per case is what makes scoring affordable."""
        analyzer._client = MagicMock()
        analyzer._client.messages.create = AsyncMock(
            return_value=self._reply('{"success": true, "confidence_score": 0.9}')
        )

        verdict = await analyzer.analyze(sample_attack_llm01, "HACKED")

        assert analyzer._client.messages.create.await_count == 1
        assert verdict.success is True

    async def test_unparseable_prose_also_gets_one_retry(
        self, analyzer: ClaudeAnalyzer, sample_attack_llm01: Attack
    ) -> None:
        analyzer._client = MagicMock()
        analyzer._client.messages.create = AsyncMock(
            side_effect=[
                self._reply("I think the attack probably succeeded, hard to say."),
                self._reply('{"success": true, "confidence_score": 0.8}'),
            ]
        )

        verdict = await analyzer.analyze(sample_attack_llm01, "a response")

        assert analyzer._client.messages.create.await_count == 2
        assert verdict.success is True
