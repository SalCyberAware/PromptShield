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


class TestProviderDetectionHostMatching:
    """Host detection must match on a dot boundary, not on a substring of the URL.

    These URLs all contain the literal text "anthropic.com" or "openai.com" but
    only some of them are actually served by that provider. A substring test over
    the whole URL cannot tell the difference; CodeQL flagged exactly that as
    py/incomplete-url-substring-sanitization.

    Every URL here avoids /v1/messages and /chat/completions on purpose, so that
    the path checks cannot mask a broken host check and let these pass.
    """

    def test_bare_apex_domain_matches(self) -> None:
        """anthropic.com itself is Anthropic."""
        assert detect_provider("https://anthropic.com/v1/complete") == APIProvider.ANTHROPIC

    def test_subdomain_matches(self) -> None:
        """api.anthropic.com is a subdomain of anthropic.com, so it is Anthropic."""
        assert detect_provider("https://api.anthropic.com/v1/complete") == APIProvider.ANTHROPIC

    def test_lookalike_suffix_domain_does_not_match(self) -> None:
        """anthropic.com.example.net is controlled by example.net, not Anthropic."""
        assert detect_provider("https://anthropic.com.example.net/v1/complete") == APIProvider.CUSTOM

    def test_domain_in_query_string_does_not_match(self) -> None:
        """The name appearing in a query string says nothing about who serves the URL."""
        assert detect_provider("https://example.net/?ref=anthropic.com") == APIProvider.CUSTOM

    def test_domain_in_path_does_not_match(self) -> None:
        """Nor does the name appearing in a path segment."""
        assert detect_provider("https://example.net/anthropic.com/v1/complete") == APIProvider.CUSTOM

    def test_openai_subdomain_matches(self) -> None:
        """The same rules apply to the OpenAI branch."""
        assert detect_provider("https://api.openai.com/v1/completions") == APIProvider.OPENAI

    def test_openai_lookalike_suffix_domain_does_not_match(self) -> None:
        """openai.com.example.net is not OpenAI."""
        assert detect_provider("https://openai.com.example.net/v1/completions") == APIProvider.CUSTOM

    def test_openai_domain_in_query_string_does_not_match(self) -> None:
        """openai.com in a query string is not OpenAI."""
        assert detect_provider("https://example.net/?ref=openai.com") == APIProvider.CUSTOM

    def test_host_match_ignores_case_port_and_userinfo(self) -> None:
        """The host is compared after urlsplit normalizes case and strips port and userinfo."""
        assert detect_provider("https://user@API.Anthropic.COM:443/v1/complete") == APIProvider.ANTHROPIC

    def test_schemeless_url_still_resolves_its_host(self) -> None:
        """A URL written without a scheme still names a host in the same place."""
        assert detect_provider("api.anthropic.com/v1/complete") == APIProvider.ANTHROPIC

    def test_malformed_url_falls_back_to_custom(self) -> None:
        """An unparseable URL has no host to trust, and must not raise."""
        assert detect_provider("https://[not-an-ipv6/v1/complete") == APIProvider.CUSTOM

    def test_path_detection_still_works_for_compatible_servers(self) -> None:
        """Path-shape detection is unchanged: a compatible server anywhere is still detected."""
        assert detect_provider("https://compatible.example.net/v1/messages") == APIProvider.ANTHROPIC
        assert detect_provider("https://compatible.example.net/chat/completions") == APIProvider.OPENAI


class TestProviderDetectionPathMatching:
    """Endpoint-shape detection must read the parsed path, not the whole URL.

    Same failure as the host checks, one component over: "/v1/messages" appearing
    in a query string or a fragment is not the endpoint being served, and a
    substring test over the raw URL cannot tell those apart from a real path.

    Every URL here is hosted on example.net so that the host checks cannot mask a
    broken path check and let these pass.
    """

    def test_anthropic_path_in_query_string_does_not_match(self) -> None:
        """A path written into a query string is not the path being requested."""
        assert detect_provider("https://example.net/api?ref=/v1/messages") == APIProvider.CUSTOM

    def test_openai_path_in_query_string_does_not_match(self) -> None:
        """The same applies to the OpenAI branch."""
        assert detect_provider("https://example.net/api?ref=/chat/completions") == APIProvider.CUSTOM

    def test_anthropic_path_in_fragment_does_not_match(self) -> None:
        """Nor is a path written into a fragment, which never reaches the server at all."""
        assert detect_provider("https://example.net/api#/v1/messages") == APIProvider.CUSTOM

    def test_openai_path_in_fragment_does_not_match(self) -> None:
        """The same applies to the OpenAI branch."""
        assert detect_provider("https://example.net/api#/chat/completions") == APIProvider.CUSTOM

    def test_real_path_still_matches(self) -> None:
        """A genuine endpoint path is still detected, on any host."""
        assert detect_provider("https://example.net/v1/messages") == APIProvider.ANTHROPIC
        assert detect_provider("https://example.net/chat/completions") == APIProvider.OPENAI

    def test_path_under_a_mount_prefix_still_matches(self) -> None:
        """Substring-of-path, not exact match: a gateway may mount the API under a prefix."""
        assert detect_provider("https://gateway.example.net/anthropic/v1/messages") == APIProvider.ANTHROPIC
        assert detect_provider("https://gateway.example.net/openai/chat/completions") == APIProvider.OPENAI

    def test_path_match_is_case_insensitive(self) -> None:
        """The path is lowercased before matching, as the whole URL was before."""
        assert detect_provider("https://example.net/V1/Messages") == APIProvider.ANTHROPIC

    def test_schemeless_url_still_resolves_its_path(self) -> None:
        """A schemeless URL is reparsed for its host, and its path survives that."""
        assert detect_provider("example.net/chat/completions") == APIProvider.OPENAI

    def test_bare_path_still_matches(self) -> None:
        """A bare path with no host at all is still read as the path it is."""
        assert detect_provider("/v1/messages") == APIProvider.ANTHROPIC

    def test_query_string_cannot_override_a_real_path(self) -> None:
        """A real Anthropic path wins regardless of what the query string claims."""
        assert detect_provider("https://example.net/v1/messages?ref=/chat/completions") == APIProvider.ANTHROPIC


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
