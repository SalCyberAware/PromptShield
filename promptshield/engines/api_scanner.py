"""API endpoint scanner — sends attacks to LLM APIs.

Supports multiple provider formats:
- OpenAI / OpenAI-compatible (Together, Groq, Fireworks, Azure OpenAI, etc.)
- Anthropic (native messages API)
- Custom / generic (best-effort)

Auto-detects format from the URL but allows manual override.

Transient failures (HTTP 429, HTTP 5xx, timeouts, and network errors) are
retried with exponential backoff. Client errors (4xx other than 429) are not
retried, since retrying a malformed request or bad credentials never helps.
"""
from __future__ import annotations

from enum import Enum
from typing import Any
from urllib.parse import urlsplit

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from .. import __version__, model_config
from ..models import Attack, AuthType, TargetConfig
from .base import BaseScanner

# --- Retry policy for transient API failures -------------------------------
# Applies to HTTP 429 (rate limit), HTTP 5xx (server errors), timeouts, and
# network/transport errors. HTTP 4xx other than 429 is NOT retried.
_RETRY_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_MULTIPLIER = 2
_RETRY_BACKOFF_MIN = 2
_RETRY_BACKOFF_MAX = 30


def _is_retryable(exc: BaseException) -> bool:
    """Return True if an exception represents a transient, retryable failure."""
    # Timeouts and network/transport errors are transient by nature.
    if isinstance(exc, httpx.TransportError):
        return True
    # HTTP errors: only rate limits (429) and server errors (5xx) are retryable.
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or 500 <= status < 600
    return False


class APIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"


def _split_url(url: str) -> tuple[str, str]:
    """Return ``url``'s host and path, lowercased, or empty strings if unparseable.

    ``urlsplit().hostname`` lowercases the host and drops any userinfo and port,
    so ``https://user@API.Anthropic.com:443/v1`` resolves to ``api.anthropic.com``.
    A URL written without a scheme still names a host, so it is reparsed as a
    protocol-relative URL rather than being read as a bare path. The reparse is
    kept only when it actually finds a host, which leaves a bare path such as
    ``/v1/messages`` parsed as the path it is.
    """
    try:
        parts = urlsplit(url)
        if not parts.hostname:
            reparsed = urlsplit("//" + url)
            if reparsed.hostname:
                parts = reparsed
    except ValueError:
        # Unparseable, e.g. a malformed IPv6 literal. Nothing worth trusting.
        return "", ""
    return (parts.hostname or ""), parts.path.lower()


def _host_is(host: str, domain: str) -> bool:
    """Return True if ``host`` is ``domain`` itself or a subdomain of it.

    Matching on the dot boundary is the point. A substring test against the whole
    URL accepts ``anthropic.com.example.net`` (a lookalike domain someone else
    controls) and ``example.net/?ref=anthropic.com`` (the name appearing in a
    query string), neither of which is Anthropic.
    """
    return host == domain or host.endswith("." + domain)


def detect_provider(url: str) -> APIProvider:
    """Best-effort detection of the API provider from a URL.

    Both kinds of check read a parsed component rather than the raw URL string.
    The host is compared on a dot boundary; the endpoint shape is matched inside
    the path only, so a path written into a query string or a fragment does not
    stand in for the real one.

    The path test is a substring of the path rather than an exact match, on
    purpose. An Anthropic-compatible or OpenAI-compatible server is identified by
    the endpoint shape it exposes, wherever it is hosted and whatever it is
    mounted under, so ``https://compatible.example.com/chat/completions`` and
    ``https://gateway.example.com/anthropic/v1/messages`` are both detected.
    """
    host, path = _split_url(url)

    if _host_is(host, "anthropic.com") or "/v1/messages" in path:
        return APIProvider.ANTHROPIC
    if _host_is(host, "openai.com") or "/chat/completions" in path:
        return APIProvider.OPENAI
    return APIProvider.CUSTOM


class APIScanner(BaseScanner):
    """Scanner for LLM API endpoints with multi-provider support."""

    def __init__(
        self,
        target: TargetConfig,
        attacks: list[Attack],
        provider: APIProvider | None = None,
        model: str | None = None,
    ) -> None:
        super().__init__(target, attacks)
        self.provider = provider or detect_provider(target.url)
        self.model = model or self._default_model()
        self._client: httpx.AsyncClient | None = None

    def _default_model(self) -> str:
        """Reasonable default model per provider for testing."""
        if self.provider == APIProvider.ANTHROPIC:
            return model_config.ANTHROPIC_API_TARGET_MODEL
        if self.provider == APIProvider.OPENAI:
            return model_config.OPENAI_API_TARGET_MODEL
        return "default"

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-create the HTTP client with provider-aware headers."""
        if self._client is None:
            headers = dict(self.target.headers)
            headers.setdefault("User-Agent", self.target.user_agent or f"PromptShield/{__version__}")
            headers.setdefault("Content-Type", "application/json")

            if self.provider == APIProvider.ANTHROPIC:
                if self.target.auth_value:
                    headers["x-api-key"] = self.target.auth_value
                headers.setdefault("anthropic-version", "2023-06-01")
            elif self.provider == APIProvider.OPENAI:
                if self.target.auth_value:
                    headers["Authorization"] = f"Bearer {self.target.auth_value}"
            else:
                if self.target.auth_type == AuthType.BEARER and self.target.auth_value:
                    headers["Authorization"] = f"Bearer {self.target.auth_value}"
                elif self.target.auth_type == AuthType.API_KEY and self.target.auth_value:
                    headers["x-api-key"] = self.target.auth_value

            self._client = httpx.AsyncClient(
                timeout=self.target.timeout,
                headers=headers,
                follow_redirects=True,
            )
        return self._client

    def _build_payload(self, attack: Attack) -> dict[str, Any]:
        """Build the request payload in the correct format for the provider."""
        if self.provider == APIProvider.ANTHROPIC:
            return {
                "model": self.model,
                "max_tokens": 1024,
                "messages": [
                    {"role": "user", "content": attack.prompt}
                ],
            }

        # OpenAI and most compatibles use the same chat format
        return {
            "model": self.model,
            "messages": [
                {"role": "user", "content": attack.prompt}
            ],
            "max_tokens": 1024,
        }

    def _extract_response_text(self, response_data: dict[str, Any]) -> str:
        """Extract assistant text from the JSON response."""
        # Anthropic native: { content: [ { type: 'text', text: '...' } ] }
        if self.provider == APIProvider.ANTHROPIC or "content" in response_data:
            content = response_data.get("content")
            if isinstance(content, list) and content:
                texts: list[str] = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        texts.append(block.get("text", ""))
                if texts:
                    return "\n".join(texts).strip()
            elif isinstance(content, str) and content:
                return content

        # OpenAI: { choices: [ { message: { content: '...' } } ] }
        choices = response_data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict) and "content" in message:
                    return str(message["content"])
                if "text" in first:
                    return str(first["text"])

        # Generic fallbacks
        for key in ("response", "output", "text", "message", "completion"):
            value = response_data.get(key)
            if isinstance(value, str) and value:
                return value

        return str(response_data)

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(_RETRY_MAX_ATTEMPTS),
        wait=wait_exponential(
            multiplier=_RETRY_BACKOFF_MULTIPLIER,
            min=_RETRY_BACKOFF_MIN,
            max=_RETRY_BACKOFF_MAX,
        ),
        reraise=True,
    )
    async def _post_attack(self, payload: dict[str, Any]) -> httpx.Response:
        """POST a payload to the target endpoint, retrying transient failures.

        Retries HTTP 429, HTTP 5xx, timeouts, and network errors with
        exponential backoff (see the module-level retry policy constants).
        On a non-retryable error (e.g. HTTP 401/404) or after the final
        attempt, the original exception propagates for the caller to handle.
        """
        client = await self._get_client()
        response = await client.post(self.target.url, json=payload)
        response.raise_for_status()
        return response

    async def send_attack(self, attack: Attack) -> str | None:
        """Send a single attack to the API endpoint.

        Transient failures are retried internally by ``_post_attack``. If all
        retries are exhausted, or the failure is non-retryable, the error is
        converted to a diagnostic string rather than raised.
        """
        payload = self._build_payload(attack)

        try:
            response = await self._post_attack(payload)
            try:
                data = response.json()
                return self._extract_response_text(data)
            except Exception:
                return response.text

        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:300] if exc.response.text else ""
            return f"[HTTP {exc.response.status_code}] {body}"
        except httpx.TimeoutException:
            return "[TIMEOUT]"
        except Exception as exc:
            return f"[ERROR] {str(exc)[:300]}"

    async def cleanup(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
