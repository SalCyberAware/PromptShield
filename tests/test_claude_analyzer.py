"""Tests for the Claude AI analyzer (with mocked Anthropic API)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptshield.analyzers.claude_analyzer import ClaudeAnalyzer
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
