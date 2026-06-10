"""System-prompt scanner — the target IS a user-supplied system prompt.

Unlike ``APIScanner`` (which fires attacks at a third-party endpoint the user
owns), this scanner runs the attacks against a *configured system prompt* by
calling a server-side model on OUR keys. For each attack it sends:

    [system: <the user's pasted system prompt>, user: <attack.prompt>]

and returns the model's reply for the analyzers to judge. This is the one
detection-core addition that powers the "paste your system prompt, we scan it"
web product (see ``docs/WEB_ARCHITECTURE.md``).

It is a drop-in ``BaseScanner`` subclass: it implements the same two abstract
methods as ``APIScanner`` (``send_attack`` + ``cleanup``) and uses the identical
``[ERROR]``/``[TIMEOUT]`` string-prefix error convention, so ``run_scan``'s
analysis gating works unchanged and never sees a raised exception from the
target call.

The target has no real URL, so callers build the ``TargetConfig`` with an
``internal://<model>`` sentinel; that value flows through to ``Finding.target_url``.
"""
from __future__ import annotations

import os

from openai import APITimeoutError, AsyncOpenAI

from ..models import Attack, TargetConfig
from .base import BaseScanner

DEFAULT_TARGET_MODEL = "gpt-4o-mini"

# Cap the target reply we hand to the analyzers (matches APIScanner's max_tokens
# request budget). The transcript layer truncates separately.
_TARGET_MAX_TOKENS = 1024


def default_target_model() -> str:
    """Resolve the server-side target model (env override, else the cheap default)."""
    return os.getenv("PROMPTSHIELD_TARGET_MODEL") or DEFAULT_TARGET_MODEL


def internal_target_url(model: str) -> str:
    """Build the sentinel URL used for system-prompt targets (no real endpoint)."""
    return f"internal://{model}"


class SystemPromptScanner(BaseScanner):
    """Scanner that attacks a user-supplied system prompt via a server-side model.

    Constructor key precedence mirrors ``OpenAIAnalyzer``:
    ``PROMPTSHIELD_TARGET_OPENAI_KEY`` → ``OPENAI_API_KEY`` (explicit ``api_key``
    arg wins over both). Model precedence: explicit ``model`` arg →
    ``PROMPTSHIELD_TARGET_MODEL`` → ``"gpt-4o-mini"``.
    """

    def __init__(
        self,
        target: TargetConfig,
        attacks: list[Attack],
        system_prompt: str,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        super().__init__(target, attacks)
        self.system_prompt = system_prompt
        self.model = model or default_target_model()
        self.api_key = (
            api_key
            or os.getenv("PROMPTSHIELD_TARGET_OPENAI_KEY")
            or os.getenv("OPENAI_API_KEY")
        )

        if not self.api_key:
            raise ValueError(
                "No OpenAI API key found for SystemPromptScanner. Set "
                "PROMPTSHIELD_TARGET_OPENAI_KEY or OPENAI_API_KEY in the environment."
            )

        self._client: AsyncOpenAI | None = None

    async def _get_client(self) -> AsyncOpenAI:
        """Lazy-create the AsyncOpenAI client (mirrors APIScanner's lazy client)."""
        if self._client is None:
            self._client = AsyncOpenAI(api_key=self.api_key)
        return self._client

    def _extract_response_text(self, completion: object) -> str:
        """Pull assistant text out of a chat completion, tolerating empty choices."""
        choices = getattr(completion, "choices", None)
        if choices:
            message = getattr(choices[0], "message", None)
            content = getattr(message, "content", None)
            if content:
                return str(content)
        return ""

    async def send_attack(self, attack: Attack) -> str | None:
        """Run one attack against the configured system prompt.

        Sends ``[system: user's prompt, user: attack.prompt]`` to the target
        model. Converts a timeout to ``[TIMEOUT]`` and any other failure to an
        ``[ERROR] ...`` string — the same convention ``APIScanner`` uses — so the
        scan loop's analysis gating works unchanged. Never raises.
        """
        try:
            client = await self._get_client()
            completion = await client.chat.completions.create(
                model=self.model,
                max_tokens=_TARGET_MAX_TOKENS,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": attack.prompt},
                ],
            )
            return self._extract_response_text(completion)
        except APITimeoutError:
            return "[TIMEOUT]"
        except Exception as exc:
            return f"[ERROR] {str(exc)[:300]}"

    async def cleanup(self) -> None:
        """Close the AsyncOpenAI client (mirrors APIScanner.cleanup)."""
        if self._client is not None:
            await self._client.close()
            self._client = None
