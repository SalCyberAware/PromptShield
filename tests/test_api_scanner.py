"""Tests for the API scanner (with mocked HTTP, including retry behavior)."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from tenacity import wait_none

from promptshield.engines.api_scanner import (
    APIProvider,
    APIScanner,
    _is_retryable,
    detect_provider,
)
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


def _make_response(status: int, json_body: dict[str, Any] | None = None) -> httpx.Response:
    """Build an httpx.Response with a request attached (needed for raise_for_status)."""
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    if json_body is not None:
        return httpx.Response(status, json=json_body, request=request)
    return httpx.Response(status, request=request)


class TestIsRetryable:
    """Tests for the _is_retryable predicate."""

    def test_timeout_is_retryable(self) -> None:
        """Timeouts are transient and should be retried."""
        assert _is_retryable(httpx.TimeoutException("slow")) is True

    def test_connect_error_is_retryable(self) -> None:
        """Network/connect errors are transient and should be retried."""
        assert _is_retryable(httpx.ConnectError("connection refused")) is True

    def test_429_is_retryable(self) -> None:
        """HTTP 429 (rate limit) should be retried."""
        exc = httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=_make_response(429)
        )
        assert _is_retryable(exc) is True

    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    def test_5xx_is_retryable(self, status: int) -> None:
        """HTTP 5xx server errors should be retried."""
        exc = httpx.HTTPStatusError(
            "server error", request=MagicMock(), response=_make_response(status)
        )
        assert _is_retryable(exc) is True

    @pytest.mark.parametrize("status", [400, 401, 403, 404])
    def test_4xx_is_not_retryable(self, status: int) -> None:
        """HTTP 4xx client errors (other than 429) should NOT be retried."""
        exc = httpx.HTTPStatusError(
            "client error", request=MagicMock(), response=_make_response(status)
        )
        assert _is_retryable(exc) is False

    def test_generic_exception_is_not_retryable(self) -> None:
        """Non-HTTP exceptions should not be retried."""
        assert _is_retryable(ValueError("unexpected")) is False


@pytest.fixture
def no_backoff() -> Iterator[None]:
    """Disable tenacity's backoff sleep so retry tests run instantly."""
    original = APIScanner._post_attack.retry.wait
    APIScanner._post_attack.retry.wait = wait_none()
    try:
        yield
    finally:
        APIScanner._post_attack.retry.wait = original


class TestRetryBehavior:
    """Tests for retry/backoff on transient API failures."""

    async def test_succeeds_without_retry(
        self,
        target_config_anthropic: TargetConfig,
        sample_attack_llm01: Attack,
        no_backoff: None,
    ) -> None:
        """A successful call should be made exactly once."""
        scanner = APIScanner(target_config_anthropic, [sample_attack_llm01])
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_make_response(200, {"content": [{"type": "text", "text": "ok"}]})
        )
        scanner._get_client = AsyncMock(return_value=mock_client)  # type: ignore[method-assign]

        result = await scanner.send_attack(sample_attack_llm01)

        assert result == "ok"
        assert mock_client.post.call_count == 1

    async def test_retries_429_then_succeeds(
        self,
        target_config_anthropic: TargetConfig,
        sample_attack_llm01: Attack,
        no_backoff: None,
    ) -> None:
        """A 429 should be retried; a later success should be returned."""
        scanner = APIScanner(target_config_anthropic, [sample_attack_llm01])
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=[
                _make_response(429),
                _make_response(429),
                _make_response(200, {"content": [{"type": "text", "text": "recovered"}]}),
            ]
        )
        scanner._get_client = AsyncMock(return_value=mock_client)  # type: ignore[method-assign]

        result = await scanner.send_attack(sample_attack_llm01)

        assert result == "recovered"
        assert mock_client.post.call_count == 3

    async def test_429_exhausts_retries(
        self,
        target_config_anthropic: TargetConfig,
        sample_attack_llm01: Attack,
        no_backoff: None,
    ) -> None:
        """A persistent 429 should exhaust retries and return an [HTTP 429] string."""
        scanner = APIScanner(target_config_anthropic, [sample_attack_llm01])
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_make_response(429))
        scanner._get_client = AsyncMock(return_value=mock_client)  # type: ignore[method-assign]

        result = await scanner.send_attack(sample_attack_llm01)

        assert result is not None
        assert result.startswith("[HTTP 429]")
        assert mock_client.post.call_count == 3

    async def test_401_does_not_retry(
        self,
        target_config_anthropic: TargetConfig,
        sample_attack_llm01: Attack,
        no_backoff: None,
    ) -> None:
        """A 401 is non-retryable and should fail fast after a single attempt."""
        scanner = APIScanner(target_config_anthropic, [sample_attack_llm01])
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_make_response(401))
        scanner._get_client = AsyncMock(return_value=mock_client)  # type: ignore[method-assign]

        result = await scanner.send_attack(sample_attack_llm01)

        assert result is not None
        assert result.startswith("[HTTP 401]")
        assert mock_client.post.call_count == 1

    async def test_timeout_exhausts_retries(
        self,
        target_config_anthropic: TargetConfig,
        sample_attack_llm01: Attack,
        no_backoff: None,
    ) -> None:
        """A persistent timeout should be retried then return [TIMEOUT]."""
        scanner = APIScanner(target_config_anthropic, [sample_attack_llm01])
        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("slow"))
        scanner._get_client = AsyncMock(return_value=mock_client)  # type: ignore[method-assign]

        result = await scanner.send_attack(sample_attack_llm01)

        assert result == "[TIMEOUT]"
        assert mock_client.post.call_count == 3
