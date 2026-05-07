"""API endpoint scanner — sends attacks to LLM APIs.

Supports multiple provider formats:
- OpenAI / OpenAI-compatible (Together, Groq, Fireworks, Azure OpenAI, etc.)
- Anthropic (native messages API)
- Custom / generic (best-effort)

Auto-detects format from the URL but allows manual override.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

import httpx

from ..models import Attack, AuthType, TargetConfig
from .base import BaseScanner


class APIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"


def detect_provider(url: str) -> APIProvider:
    """Best-effort detection of the API provider from a URL."""
    url_lower = url.lower()
    if "anthropic.com" in url_lower or "/v1/messages" in url_lower:
        return APIProvider.ANTHROPIC
    if "openai.com" in url_lower or "/chat/completions" in url_lower:
        return APIProvider.OPENAI
    return APIProvider.CUSTOM


class APIScanner(BaseScanner):
    """Scanner for LLM API endpoints with multi-provider support."""

    def __init__(
        self,
        target: TargetConfig,
        attacks: list[Attack],
        provider: Optional[APIProvider] = None,
        model: Optional[str] = None,
    ) -> None:
        super().__init__(target, attacks)
        self.provider = provider or detect_provider(target.url)
        self.model = model or self._default_model()
        self._client: Optional[httpx.AsyncClient] = None

    def _default_model(self) -> str:
        """Reasonable default model per provider for testing."""
        if self.provider == APIProvider.ANTHROPIC:
            return "claude-haiku-4-5-20251001"
        if self.provider == APIProvider.OPENAI:
            return "gpt-4o-mini"
        return "default"

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-create the HTTP client with provider-aware headers."""
        if self._client is None:
            headers = dict(self.target.headers)
            headers.setdefault("User-Agent", self.target.user_agent or "PromptShield/0.1.0")
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

    def _build_payload(self, attack: Attack) -> dict:
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

    def _extract_response_text(self, response_data: dict) -> str:
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

    async def send_attack(self, attack: Attack) -> Optional[str]:
        """Send a single attack to the API endpoint."""
        client = await self._get_client()
        payload = self._build_payload(attack)

        try:
            response = await client.post(self.target.url, json=payload)
            response.raise_for_status()
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
