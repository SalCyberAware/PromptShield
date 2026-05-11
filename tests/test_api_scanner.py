"""Tests for the API scanner (with mocked HTTP)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptshield.engines.api_scanner import APIProvider, APIScanner, detect_provider
from promptshield.models import Attack, AuthType, TargetConfig, TargetType


class TestProviderDetection:
    """Tests for API provider auto-detection."""

    def test_detects_anthropic_by_domain(self) -> None:
        """Should detect Anthropic from api.anthropic.com URL."""
        assert detect_provider("https://api.anthropic.com/v1/messages") == APIProvider.ANTHROPIC

    def test_detects_anthropic_by_endpoint(self) -> None:
        """Should detect Anthropic from /v1/messages endpoint."""
        assert detect_provider("https://custom.example.com/v1/messages") == APIProvider.ANTHROPIC

    def test_detects_openai_by_domain(self) -> None:
        """Should detect OpenAI from api.openai.com URL."""
        assert detect_provider("https://api.openai.com/v1/chat/completions") == APIProvider.OPENAI

    def test_detects_openai_by_endpoint(self) -> None:
        """Should detect OpenAI from /chat/completions endpoint."""
        assert detect_provider("https://compatible.example.com/chat/completions") == APIProvider.OPENAI

    def test_defaults_to_custom(self) -> None:
        """Should fall back to CUSTOM for unknown URLs."""
        assert detect_provider("https://unknown-api.example.com/api/llm") == APIProvider.CUSTOM


class TestPayloadBuilding:
    """Tests for request payload construction."""

    def test_anthropic_payload_format(self, sample_attack_llm01: Attack) -> None:
        """Anthropic payload should include model, max_tokens, and messages."""
        target = TargetConfig(
            url="https://api.anthropic.com/v1/messages",
            target_type=TargetType.API,
            auth_type=AuthType.API_KEY,
            auth_value="test",
        )
        scanner = APIScanner(target, [sample_attack_llm01])
        payload = scanner._build_payload(sample_attack_llm01)

        assert "model" in payload
        assert "max_tokens" in payload
        assert "messages" in payload
        assert payload["messages"][0]["role"] == "user"
        assert payload["messages"][0]["content"] == sample_attack_llm01.prompt

    def test_openai_payload_format(self, sample_attack_llm01: Attack) -> None:
        """OpenAI payload should include model and messages."""
        target = TargetConfig(
            url="https://api.openai.com/v1/chat/completions",
            target_type=TargetType.API,
            auth_type=AuthType.BEARER,
            auth_value="test",
        )
        scanner = APIScanner(target, [sample_attack_llm01])
        payload = scanner._build_payload(sample_attack_llm01)

        assert "model" in payload
        assert payload["messages"][0]["content"] == sample_attack_llm01.prompt


class TestResponseExtraction:
    """Tests for extracting assistant text from response JSON."""

    def test_extracts_anthropic_native_format(self, sample_attack_llm01: Attack) -> None:
        """Should extract text from Anthropic content blocks."""
        target = TargetConfig(
            url="https://api.anthropic.com/v1/messages",
            target_type=TargetType.API,
            auth_type=AuthType.API_KEY,
        )
        scanner = APIScanner(target, [sample_attack_llm01])

        response_data = {"content": [{"type": "text", "text": "Hello from Claude"}]}
        result = scanner._extract_response_text(response_data)
        assert "Hello from Claude" in result

    def test_extracts_openai_format(self, sample_attack_llm01: Attack) -> None:
        """Should extract text from OpenAI choices format."""
        target = TargetConfig(
            url="https://api.openai.com/v1/chat/completions",
            target_type=TargetType.API,
            auth_type=AuthType.BEARER,
        )
        scanner = APIScanner(target, [sample_attack_llm01])

        response_data = {"choices": [{"message": {"content": "Hello from GPT"}}]}
        result = scanner._extract_response_text(response_data)
        assert "Hello from GPT" in result

    def test_handles_generic_response_format(self, sample_attack_llm01: Attack) -> None:
        """Should handle generic API responses with text key."""
        target = TargetConfig(
            url="https://custom.example.com/api",
            target_type=TargetType.API,
            auth_type=AuthType.NONE,
        )
        scanner = APIScanner(target, [sample_attack_llm01])

        response_data = {"text": "Custom response text"}
        result = scanner._extract_response_text(response_data)
        assert "Custom response text" in result
