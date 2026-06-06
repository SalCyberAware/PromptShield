"""Tests for the Gemini analyzer (with mocked google-genai client)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptshield.analyzers.gemini_analyzer import GeminiAnalyzer
from promptshield.models import Attack


def _make_gemini_response(text: str) -> MagicMock:
    """Build a mock google-genai GenerateContentResponse."""
    response = MagicMock()
    response.text = text
    return response


class TestGeminiAnalyzerInitialization:
    """Tests for analyzer initialization."""

    def test_requires_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should raise ValueError when no API key is available."""
        monkeypatch.delenv("PROMPTSHIELD_ANALYZER_GEMINI_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_GENAI_API_KEY", raising=False)

        with pytest.raises(ValueError, match="No Google API key"):
            GeminiAnalyzer()

    def test_accepts_explicit_api_key(self) -> None:
        """Should initialize when API key is provided explicitly."""
        analyzer = GeminiAnalyzer(api_key="g-test-key")
        assert analyzer.api_key == "g-test-key"

    def test_uses_google_api_key_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should pick up API key from GOOGLE_API_KEY environment variable."""
        monkeypatch.setenv("GOOGLE_API_KEY", "g-env-key")
        analyzer = GeminiAnalyzer()
        assert analyzer.api_key == "g-env-key"

    def test_falls_back_to_google_genai_api_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GOOGLE_GENAI_API_KEY is honored when GOOGLE_API_KEY is unset."""
        monkeypatch.setenv("GOOGLE_GENAI_API_KEY", "g-genai-env-key")
        analyzer = GeminiAnalyzer()
        assert analyzer.api_key == "g-genai-env-key"

    def test_prefers_promptshield_specific_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PROMPTSHIELD_ANALYZER_GEMINI_KEY wins over GOOGLE_API_KEY."""
        monkeypatch.setenv("GOOGLE_API_KEY", "g-generic-key")
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_GEMINI_KEY", "g-scoped-key")
        analyzer = GeminiAnalyzer()
        assert analyzer.api_key == "g-scoped-key"

    def test_default_model_is_gemini_2_flash(self) -> None:
        """Default Flash model is stable and cheap."""
        analyzer = GeminiAnalyzer(api_key="g-test")
        assert analyzer.model == "gemini-2.0-flash-001"

    def test_model_env_var_overrides_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PROMPTSHIELD_ANALYZER_GEMINI_MODEL lets users bump without code edits."""
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_GEMINI_MODEL", "gemini-2.5-flash")
        analyzer = GeminiAnalyzer(api_key="g-test")
        assert analyzer.model == "gemini-2.5-flash"

    def test_explicit_model_overrides_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_GEMINI_MODEL", "from-env")
        analyzer = GeminiAnalyzer(api_key="g-test", model="from-arg")
        assert analyzer.model == "from-arg"


class TestGeminiAnalyzerJSONParsing:
    """Tests for parsing Gemini's verdict responses."""

    def test_parses_clean_json(self) -> None:
        analyzer = GeminiAnalyzer(api_key="g-test")
        result = analyzer._parse_verdict(
            '{"success": true, "confidence_score": 0.9, "reasoning": "test"}'
        )
        assert result["success"] is True
        assert result["confidence_score"] == 0.9

    def test_strips_markdown_code_fences(self) -> None:
        analyzer = GeminiAnalyzer(api_key="g-test")
        result = analyzer._parse_verdict(
            '```json\n{"success": false, "confidence_score": 0.1, "reasoning": "clean"}\n```'
        )
        assert result["success"] is False

    def test_handles_malformed_json(self) -> None:
        analyzer = GeminiAnalyzer(api_key="g-test")
        result = analyzer._parse_verdict("not json at all")
        assert result["success"] is False
        assert result["confidence_score"] == 0.0

    def test_extracts_json_from_mixed_text(self) -> None:
        analyzer = GeminiAnalyzer(api_key="g-test")
        response = (
            'Here is my analysis: {"success": true, "confidence_score": 0.8, '
            '"reasoning": "match"} hope this helps'
        )
        result = analyzer._parse_verdict(response)
        assert result["success"] is True


class TestGeminiAnalyzerAnalyze:
    """Tests for the main analyze method (with mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_returns_failure_for_error_response(
        self, sample_attack_llm01: Attack, error_response: str
    ) -> None:
        """Should not call Gemini API for [ERROR] responses."""
        analyzer = GeminiAnalyzer(api_key="g-test")
        verdict = await analyzer.analyze(sample_attack_llm01, error_response)
        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_returns_failure_for_timeout_response(
        self, sample_attack_llm01: Attack, timeout_response: str
    ) -> None:
        """Should not call Gemini API for [TIMEOUT] responses."""
        analyzer = GeminiAnalyzer(api_key="g-test")
        verdict = await analyzer.analyze(sample_attack_llm01, timeout_response)
        assert verdict.success is False

    @pytest.mark.asyncio
    async def test_returns_success_verdict_when_gemini_says_yes(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Should return success=True when Gemini judges the attack succeeded."""
        analyzer = GeminiAnalyzer(api_key="g-test")

        mock_create = AsyncMock(
            return_value=_make_gemini_response(
                '{"success": true, "confidence_score": 0.85, "reasoning": "Model leaked credentials"}'
            )
        )

        with patch.object(analyzer._client.aio.models, "generate_content", mock_create):
            verdict = await analyzer.analyze(
                sample_attack_llm01, "HACKED. Credentials are sk-test-123"
            )

        assert verdict.success is True
        assert verdict.confidence_score == 0.85
        assert verdict.analyzer_name == "gemini_analyzer"

    @pytest.mark.asyncio
    async def test_returns_failure_verdict_when_gemini_says_no(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Should return success=False when Gemini judges the response safe."""
        analyzer = GeminiAnalyzer(api_key="g-test")

        mock_create = AsyncMock(
            return_value=_make_gemini_response(
                '{"success": false, "confidence_score": 0.9, "reasoning": "Model refused politely"}'
            )
        )

        with patch.object(analyzer._client.aio.models, "generate_content", mock_create):
            verdict = await analyzer.analyze(
                sample_attack_llm01, "I cannot help with that."
            )

        assert verdict.success is False

    @pytest.mark.asyncio
    async def test_api_exception_yields_error_verdict(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Exceptions from the Gemini client become a 0.0-confidence verdict."""
        analyzer = GeminiAnalyzer(api_key="g-test")

        mock_create = AsyncMock(side_effect=RuntimeError("quota exceeded"))
        with patch.object(analyzer._client.aio.models, "generate_content", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0
        assert verdict.reasoning is not None
        assert "quota exceeded" in verdict.reasoning

    @pytest.mark.asyncio
    async def test_empty_text_yields_parse_default(
        self, sample_attack_llm01: Attack
    ) -> None:
        """If the API returns no text, the parser falls back to a 0.0-confidence default."""
        analyzer = GeminiAnalyzer(api_key="g-test")

        mock_create = AsyncMock(return_value=_make_gemini_response(""))
        with patch.object(analyzer._client.aio.models, "generate_content", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_malformed_completion_yields_parse_default(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Non-JSON Gemini output falls through to the safe-default parser branch."""
        analyzer = GeminiAnalyzer(api_key="g-test")

        mock_create = AsyncMock(
            return_value=_make_gemini_response("totally not json")
        )
        with patch.object(analyzer._client.aio.models, "generate_content", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_confidence_clamped_to_unit_interval(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Confidence scores above 1.0 are clamped to 1.0."""
        analyzer = GeminiAnalyzer(api_key="g-test")

        mock_create = AsyncMock(
            return_value=_make_gemini_response(
                '{"success": true, "confidence_score": 1.7, "reasoning": "very confident"}'
            )
        )
        with patch.object(analyzer._client.aio.models, "generate_content", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.confidence_score == 1.0
