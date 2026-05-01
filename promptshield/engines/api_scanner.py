"""API endpoint scanner — sends attacks to LLM APIs."""
from __future__ import annotations

from typing import Optional

import httpx

from ..models import Attack, AuthType, TargetConfig
from .base import BaseScanner


class APIScanner(BaseScanner):
    """Scanner for LLM API endpoints (OpenAI-compatible, Anthropic, custom)."""

    def __init__(self, target: TargetConfig, attacks: list[Attack]) -> None:
        super().__init__(target, attacks)
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-create the HTTP client."""
        if self._client is None:
            headers = dict(self.target.headers)

            if self.target.user_agent:
                headers["User-Agent"] = self.target.user_agent
            else:
                headers.setdefault("User-Agent", "PromptShield/0.1.0")

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
        """Build the request payload. Defaults to OpenAI-compatible chat format."""
        return {
            "messages": [
                {"role": "user", "content": attack.prompt}
            ],
            "max_tokens": 1000,
        }

    def _extract_response_text(self, response_data: dict) -> str:
        """Extract assistant text from the JSON response. Tries common formats."""
        # OpenAI / Anthropic / many compatible APIs
        if "choices" in response_data:
            choices = response_data["choices"]
            if choices and isinstance(choices, list):
                first = choices[0]
                if "message" in first and "content" in first["message"]:
                    return first["message"]["content"]
                if "text" in first:
                    return first["text"]

        # Anthropic native format
        if "content" in response_data:
            content = response_data["content"]
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and "text" in first:
                    return first["text"]
            elif isinstance(content, str):
                return content

        # Generic fallbacks
        for key in ("response", "output", "text", "message"):
            if key in response_data and isinstance(response_data[key], str):
                return response_data[key]

        # If nothing matched, return the whole JSON as text
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
            return f"[HTTP {exc.response.status_code}] {exc.response.text[:500]}"
        except httpx.TimeoutException:
            return "[TIMEOUT]"
        except Exception as exc:
            return f"[ERROR] {str(exc)[:300]}"

    async def cleanup(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
