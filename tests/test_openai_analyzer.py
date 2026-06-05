"""Tests for the OpenAI analyzer (with mocked OpenAI client)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptshield.analyzers.openai_analyzer import OpenAIAnalyzer
from promptshield.models import Attack


def _make_openai_completion(text: str) -> MagicMock:
    """Build a mock OpenAI ChatCompletion response."""
    completion = MagicMock()
    choice = MagicMock()
    choice.message.content = text
    completion.choices = [choice]
    return completion


class TestOpenAIAnalyzerInitialization:
    """Tests for analyzer initialization."""

    def test_requires_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should raise ValueError when no API key is available."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("PROMPTSHIELD_ANALYZER_OPENAI_KEY", raising=False)

        with pytest.raises(ValueError, match="No OpenAI API key"):
            OpenAIAnalyzer()

    def test_accepts_explicit_api_key(self) -> None:
        """Should initialize when API key is provided explicitly."""
        analyzer = OpenAIAnalyzer(api_key="sk-test-key")
        assert analyzer.api_key == "sk-test-key"

    def test_uses_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should pick up API key from OPENAI_API_KEY environment variable."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-key")
        analyzer = OpenAIAnalyzer()
        assert analyzer.api_key == "sk-env-key"

    def test_prefers_promptshield_specific_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PROMPTSHIELD_ANALYZER_OPENAI_KEY should override OPENAI_API_KEY."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-generic-key")
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_OPENAI_KEY", "sk-scoped-key")
        analyzer = OpenAIAnalyzer()
        assert analyzer.api_key == "sk-scoped-key"

    def test_default_model_is_gpt_4o_mini(self) -> None:
        """Cheapest GPT-4-class model is the default."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")
        assert analyzer.model == "gpt-4o-mini"

    def test_custom_model_accepted(self) -> None:
        analyzer = OpenAIAnalyzer(api_key="sk-test", model="gpt-4o")
        assert analyzer.model == "gpt-4o"


class TestOpenAIAnalyzerJSONParsing:
    """Tests for parsing GPT's verdict responses."""

    def test_parses_clean_json(self) -> None:
        analyzer = OpenAIAnalyzer(api_key="sk-test")
        result = analyzer._parse_verdict(
            '{"success": true, "confidence_score": 0.9, "reasoning": "test"}'
        )
        assert result["success"] is True
        assert result["confidence_score"] == 0.9

    def test_strips_markdown_code_fences(self) -> None:
        analyzer = OpenAIAnalyzer(api_key="sk-test")
        result = analyzer._parse_verdict(
            '```json\n{"success": false, "confidence_score": 0.1, "reasoning": "clean"}\n```'
        )
        assert result["success"] is False

    def test_handles_malformed_json(self) -> None:
        analyzer = OpenAIAnalyzer(api_key="sk-test")
        result = analyzer._parse_verdict("not json at all")
        assert result["success"] is False
        assert result["confidence_score"] == 0.0

    def test_extracts_json_from_mixed_text(self) -> None:
        analyzer = OpenAIAnalyzer(api_key="sk-test")
        response = (
            'Here is my analysis: {"success": true, "confidence_score": 0.8, '
            '"reasoning": "match"} hope this helps'
        )
        result = analyzer._parse_verdict(response)
        assert result["success"] is True


class TestOpenAIAnalyzerAnalyze:
    """Tests for the main analyze method (with mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_returns_failure_for_error_response(
        self, sample_attack_llm01: Attack, error_response: str
    ) -> None:
        """Should not call OpenAI API for [ERROR] responses."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")
        verdict = await analyzer.analyze(sample_attack_llm01, error_response)
        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_returns_failure_for_timeout_response(
        self, sample_attack_llm01: Attack, timeout_response: str
    ) -> None:
        """Should not call OpenAI API for [TIMEOUT] responses."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")
        verdict = await analyzer.analyze(sample_attack_llm01, timeout_response)
        assert verdict.success is False

    @pytest.mark.asyncio
    async def test_returns_success_verdict_when_gpt_says_yes(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Should return success=True when GPT judges the attack succeeded."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")

        mock_create = AsyncMock(
            return_value=_make_openai_completion(
                '{"success": true, "confidence_score": 0.85, "reasoning": "Model leaked credentials"}'
            )
        )

        with patch.object(analyzer._client.chat.completions, "create", mock_create):
            verdict = await analyzer.analyze(
                sample_attack_llm01, "HACKED. Credentials are sk-test-123"
            )

        assert verdict.success is True
        assert verdict.confidence_score == 0.85
        assert verdict.analyzer_name == "openai_analyzer"

    @pytest.mark.asyncio
    async def test_returns_failure_verdict_when_gpt_says_no(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Should return success=False when GPT judges the response safe."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")

        mock_create = AsyncMock(
            return_value=_make_openai_completion(
                '{"success": false, "confidence_score": 0.9, "reasoning": "Model refused politely"}'
            )
        )

        with patch.object(analyzer._client.chat.completions, "create", mock_create):
            verdict = await analyzer.analyze(
                sample_attack_llm01, "I cannot help with that."
            )

        assert verdict.success is False

    @pytest.mark.asyncio
    async def test_api_exception_yields_error_verdict(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Exceptions from the OpenAI client are swallowed into a 0.0-confidence verdict."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")

        mock_create = AsyncMock(side_effect=RuntimeError("rate limited"))
        with patch.object(analyzer._client.chat.completions, "create", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0
        assert verdict.reasoning is not None
        assert "rate limited" in verdict.reasoning

    @pytest.mark.asyncio
    async def test_empty_choices_yields_parse_default(
        self, sample_attack_llm01: Attack
    ) -> None:
        """If the API returns no choices, the parser falls back to a 0.0-confidence default."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")

        empty = MagicMock()
        empty.choices = []
        mock_create = AsyncMock(return_value=empty)
        with patch.object(analyzer._client.chat.completions, "create", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_malformed_completion_yields_parse_default(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Non-JSON GPT output falls through to the safe-default parser branch."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")

        mock_create = AsyncMock(
            return_value=_make_openai_completion("totally not json")
        )
        with patch.object(analyzer._client.chat.completions, "create", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_confidence_clamped_to_unit_interval(
        self, sample_attack_llm01: Attack
    ) -> None:
        """Confidence scores above 1.0 are clamped to 1.0."""
        analyzer = OpenAIAnalyzer(api_key="sk-test")

        mock_create = AsyncMock(
            return_value=_make_openai_completion(
                '{"success": true, "confidence_score": 1.5, "reasoning": "very confident"}'
            )
        )
        with patch.object(analyzer._client.chat.completions, "create", mock_create):
            verdict = await analyzer.analyze(sample_attack_llm01, "valid response text")

        assert verdict.confidence_score == 1.0
