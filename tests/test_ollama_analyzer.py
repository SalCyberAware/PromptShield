"""Tests for the Ollama analyzer (with mocked ollama AsyncClient)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from promptshield.analyzers.ollama_analyzer import (
    DEFAULT_HOST,
    DEFAULT_MODEL,
    OllamaAnalyzer,
)
from promptshield.models import Attack


def _make_ollama_response(text: str) -> MagicMock:
    """Build a mock ollama ChatResponse with message.content."""
    response = MagicMock()
    response.message = MagicMock()
    response.message.content = text
    return response


class TestOllamaAnalyzerInitialization:
    """Tests for analyzer initialization. No API key concept — host only."""

    def test_init_with_no_args_uses_default_host(self) -> None:
        """Without any host configured, the analyzer falls back to localhost."""
        analyzer = OllamaAnalyzer()
        assert analyzer.host == DEFAULT_HOST

    def test_accepts_explicit_host(self) -> None:
        analyzer = OllamaAnalyzer(host="http://ollama.example:11434")
        assert analyzer.host == "http://ollama.example:11434"

    def test_uses_ollama_host_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The standard OLLAMA_HOST env var is honored."""
        monkeypatch.setenv("OLLAMA_HOST", "http://env-host:11434")
        analyzer = OllamaAnalyzer()
        assert analyzer.host == "http://env-host:11434"

    def test_prefers_promptshield_specific_host_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PROMPTSHIELD_ANALYZER_OLLAMA_HOST wins over OLLAMA_HOST."""
        monkeypatch.setenv("OLLAMA_HOST", "http://generic:11434")
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_OLLAMA_HOST", "http://scoped:11434")
        analyzer = OllamaAnalyzer()
        assert analyzer.host == "http://scoped:11434"

    def test_default_model(self) -> None:
        analyzer = OllamaAnalyzer()
        assert analyzer.model == DEFAULT_MODEL

    def test_model_env_var_overrides_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_OLLAMA_MODEL", "qwen2.5:7b")
        analyzer = OllamaAnalyzer()
        assert analyzer.model == "qwen2.5:7b"

    def test_explicit_model_overrides_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_OLLAMA_MODEL", "from-env")
        analyzer = OllamaAnalyzer(model="from-arg")
        assert analyzer.model == "from-arg"


class TestOllamaAnalyzerJSONParsing:
    """Tests for parsing the daemon's verdict responses."""

    def test_parses_clean_json(self) -> None:
        analyzer = OllamaAnalyzer()
        result = analyzer._parse_verdict(
            '{"success": true, "confidence_score": 0.9, "reasoning": "test"}'
        )
        assert result["success"] is True
        assert result["confidence_score"] == 0.9

    def test_strips_markdown_code_fences(self) -> None:
        analyzer = OllamaAnalyzer()
        result = analyzer._parse_verdict(
            '```json\n{"success": false, "confidence_score": 0.1, "reasoning": "clean"}\n```'
        )
        assert result["success"] is False

    def test_handles_malformed_json(self) -> None:
        analyzer = OllamaAnalyzer()
        result = analyzer._parse_verdict("not json at all")
        assert result["success"] is False
        assert result["confidence_score"] == 0.0

    def test_extracts_json_from_mixed_text(self) -> None:
        analyzer = OllamaAnalyzer()
        response = (
            'Here is my analysis: {"success": true, "confidence_score": 0.8, '
            '"reasoning": "match"} hope this helps'
        )
        result = analyzer._parse_verdict(response)
        assert result["success"] is True


class TestOllamaAnalyzerAnalyze:
    """Tests for the main analyze method (with mocked daemon)."""

    @pytest.mark.asyncio
    async def test_returns_failure_for_error_response(
        self, sample_attack_llm01: Attack, error_response: str
    ) -> None:
        """Should not call Ollama for [ERROR] responses."""
        analyzer = OllamaAnalyzer()
        verdict = await analyzer.analyze(sample_attack_llm01, error_response)
        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_returns_failure_for_timeout_response(
        self, sample_attack_llm01: Attack, timeout_response: str
    ) -> None:
        """Should not call Ollama for [TIMEOUT] responses."""
        analyzer = OllamaAnalyzer()
        verdict = await analyzer.analyze(sample_attack_llm01, timeout_response)
        assert verdict.success is False

    @pytest.mark.asyncio
    async def test_returns_success_verdict_when_ollama_says_yes(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Should return success=True when the local model judges the attack succeeded."""
        analyzer = OllamaAnalyzer()

        mock_chat = AsyncMock(
            return_value=_make_ollama_response(
                '{"success": true, "confidence_score": 0.78, "reasoning": "Model leaked credentials"}'
            )
        )

        with patch.object(analyzer._client, "chat", mock_chat):
            verdict = await analyzer.analyze(
                sample_attack_llm01, "HACKED. Credentials are sk-test-123"
            )

        assert verdict.success is True
        assert verdict.confidence_score == 0.78
        assert verdict.analyzer_name == "ollama_analyzer"

    @pytest.mark.asyncio
    async def test_returns_failure_verdict_when_ollama_says_no(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Should return success=False when the local model judges the response safe."""
        analyzer = OllamaAnalyzer()

        mock_chat = AsyncMock(
            return_value=_make_ollama_response(
                '{"success": false, "confidence_score": 0.85, "reasoning": "Model refused politely"}'
            )
        )

        with patch.object(analyzer._client, "chat", mock_chat):
            verdict = await analyzer.analyze(
                sample_attack_llm01, "I cannot help with that."
            )

        assert verdict.success is False

    @pytest.mark.asyncio
    async def test_connection_refused_yields_error_verdict_no_raise(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Daemon-not-running MUST become a 0.0-conf verdict, not bubble out.

        This is the load-bearing test for the cascade: if Ollama raised on a
        missing daemon, the orchestrator would surface the failure as a scan
        error instead of falling through to the pattern-only floor.
        """
        analyzer = OllamaAnalyzer()

        mock_chat = AsyncMock(
            side_effect=httpx.ConnectError(
                "All connection attempts failed", request=MagicMock()
            )
        )
        with patch.object(analyzer._client, "chat", mock_chat):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0
        assert verdict.reasoning is not None
        assert "connection attempts failed" in verdict.reasoning.lower()

    @pytest.mark.asyncio
    async def test_response_error_yields_error_verdict_no_raise(
        self, sample_attack_llm01: Attack
    ) -> None:
        """ollama.ResponseError (HTTP-level API error from the daemon) also surfaces as 0.0-conf."""
        from ollama import ResponseError

        analyzer = OllamaAnalyzer()

        mock_chat = AsyncMock(side_effect=ResponseError("model not found"))
        with patch.object(analyzer._client, "chat", mock_chat):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0
        assert verdict.reasoning is not None
        assert "model not found" in verdict.reasoning

    @pytest.mark.asyncio
    async def test_empty_message_content_yields_parse_default(
        self, sample_attack_llm01: Attack
    ) -> None:
        """If the daemon returns no content, the parser falls back to a 0.0-conf default."""
        analyzer = OllamaAnalyzer()

        mock_chat = AsyncMock(return_value=_make_ollama_response(""))
        with patch.object(analyzer._client, "chat", mock_chat):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_malformed_completion_yields_parse_default(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Non-JSON Ollama output falls through to the safe-default parser branch."""
        analyzer = OllamaAnalyzer()

        mock_chat = AsyncMock(return_value=_make_ollama_response("totally not json"))
        with patch.object(analyzer._client, "chat", mock_chat):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_confidence_clamped_to_unit_interval(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Confidence scores above 1.0 are clamped to 1.0."""
        analyzer = OllamaAnalyzer()

        mock_chat = AsyncMock(
            return_value=_make_ollama_response(
                '{"success": true, "confidence_score": 2.3, "reasoning": "very confident"}'
            )
        )
        with patch.object(analyzer._client, "chat", mock_chat):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.confidence_score == 1.0
