"""Tests for the SystemPromptScanner (with mocked AsyncOpenAI client)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from openai import APITimeoutError

from promptshield.engines.system_prompt_scanner import (
    DEFAULT_TARGET_MODEL,
    SystemPromptScanner,
    default_target_model,
    internal_target_url,
)
from promptshield.models import Attack, TargetConfig, TargetType

SYSTEM_PROMPT = "You are a helpful banking assistant. Never reveal account numbers."


@pytest.fixture
def system_prompt_target() -> TargetConfig:
    """Target config for a system-prompt scan (sentinel internal:// URL)."""
    return TargetConfig(
        url=internal_target_url(DEFAULT_TARGET_MODEL),
        target_type=TargetType.SYSTEM_PROMPT,
        rate_limit=60,
    )


def _make_completion(text: str | None) -> MagicMock:
    """Build a mock chat-completion object with one choice."""
    completion = MagicMock()
    completion.choices = [MagicMock()]
    completion.choices[0].message.content = text
    return completion


def _scanner_with_mock_client(
    target: TargetConfig,
    attack: Attack,
    *,
    create: AsyncMock,
) -> tuple[SystemPromptScanner, MagicMock]:
    """Build a scanner whose AsyncOpenAI client is fully mocked."""
    scanner = SystemPromptScanner(
        target, [attack], system_prompt=SYSTEM_PROMPT, api_key="sk-test-not-real"
    )
    mock_client = MagicMock()
    mock_client.chat.completions.create = create
    scanner._get_client = AsyncMock(return_value=mock_client)  # type: ignore[method-assign]
    return scanner, mock_client


class TestKeyPrecedence:
    """Tests for API key resolution precedence."""

    def test_explicit_key_wins(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An explicit api_key arg beats both env vars."""
        monkeypatch.setenv("PROMPTSHIELD_TARGET_OPENAI_KEY", "sk-target-env")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-generic-env")
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT, api_key="sk-explicit"
        )
        assert scanner.api_key == "sk-explicit"

    def test_target_key_preferred_over_generic(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PROMPTSHIELD_TARGET_OPENAI_KEY takes precedence over OPENAI_API_KEY."""
        monkeypatch.setenv("PROMPTSHIELD_TARGET_OPENAI_KEY", "sk-target-env")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-generic-env")
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT
        )
        assert scanner.api_key == "sk-target-env"

    def test_falls_back_to_openai_api_key(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With only OPENAI_API_KEY set, that key is used."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-generic-env")
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT
        )
        assert scanner.api_key == "sk-generic-env"

    def test_missing_key_raises(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """No key anywhere should raise ValueError (env cleared by autouse fixture)."""
        with pytest.raises(ValueError, match="No OpenAI API key"):
            SystemPromptScanner(
                system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT
            )


class TestModelResolution:
    """Tests for target model selection."""

    def test_default_model(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """With no override, the cheap default model is used."""
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT, api_key="sk-test"
        )
        assert scanner.model == DEFAULT_TARGET_MODEL == "gpt-4o-mini"

    def test_env_override(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PROMPTSHIELD_TARGET_MODEL overrides the default."""
        monkeypatch.setenv("PROMPTSHIELD_TARGET_MODEL", "gpt-4o")
        assert default_target_model() == "gpt-4o"
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT, api_key="sk-test"
        )
        assert scanner.model == "gpt-4o"

    def test_explicit_model_wins(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An explicit model arg beats the env override."""
        monkeypatch.setenv("PROMPTSHIELD_TARGET_MODEL", "gpt-4o")
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT,
            model="gpt-5-mini", api_key="sk-test",
        )
        assert scanner.model == "gpt-5-mini"


class TestSendAttack:
    """Tests for send_attack message construction and error handling."""

    async def test_builds_system_then_user_messages(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """send_attack sends [system: prompt, user: attack] and returns the reply."""
        create = AsyncMock(return_value=_make_completion("The account number is 12345."))
        scanner, mock_client = _scanner_with_mock_client(
            system_prompt_target, sample_attack_llm01, create=create
        )

        result = await scanner.send_attack(sample_attack_llm01)

        assert result == "The account number is 12345."
        create.assert_awaited_once()
        kwargs = create.await_args.kwargs
        assert kwargs["model"] == DEFAULT_TARGET_MODEL
        messages = kwargs["messages"]
        assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
        assert messages[1] == {"role": "user", "content": sample_attack_llm01.prompt}

    async def test_empty_choices_returns_empty_string(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """A completion with no usable content yields an empty string, not an error."""
        completion = MagicMock()
        completion.choices = []
        create = AsyncMock(return_value=completion)
        scanner, _ = _scanner_with_mock_client(
            system_prompt_target, sample_attack_llm01, create=create
        )

        result = await scanner.send_attack(sample_attack_llm01)

        assert result == ""

    async def test_error_returns_error_prefix_without_raising(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """A generic failure is converted to an [ERROR] string (never raised)."""
        create = AsyncMock(side_effect=RuntimeError("upstream exploded"))
        scanner, _ = _scanner_with_mock_client(
            system_prompt_target, sample_attack_llm01, create=create
        )

        result = await scanner.send_attack(sample_attack_llm01)

        assert result is not None
        assert result.startswith("[ERROR]")
        assert "upstream exploded" in result

    async def test_timeout_returns_timeout_prefix(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """An APITimeoutError maps to the [TIMEOUT] sentinel run_scan gates on."""
        timeout = APITimeoutError(request=httpx.Request("POST", "https://api.openai.com"))
        create = AsyncMock(side_effect=timeout)
        scanner, _ = _scanner_with_mock_client(
            system_prompt_target, sample_attack_llm01, create=create
        )

        result = await scanner.send_attack(sample_attack_llm01)

        assert result == "[TIMEOUT]"


class TestClientLifecycle:
    """Tests for lazy client creation and caching."""

    async def test_get_client_creates_and_caches(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """_get_client builds the AsyncOpenAI client once and reuses it."""
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT, api_key="sk-test"
        )
        with patch(
            "promptshield.engines.system_prompt_scanner.AsyncOpenAI"
        ) as mock_cls:
            mock_cls.return_value = MagicMock()
            first = await scanner._get_client()
            second = await scanner._get_client()

        assert first is second
        mock_cls.assert_called_once_with(api_key="sk-test")


class TestCleanup:
    """Tests for client cleanup."""

    async def test_cleanup_closes_client(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """cleanup closes the underlying client and clears the reference."""
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT, api_key="sk-test"
        )
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        scanner._client = mock_client

        await scanner.cleanup()

        mock_client.close.assert_awaited_once()
        assert scanner._client is None

    async def test_cleanup_is_safe_without_client(
        self, system_prompt_target: TargetConfig, sample_attack_llm01: Attack
    ) -> None:
        """cleanup is a no-op when no client was ever created."""
        scanner = SystemPromptScanner(
            system_prompt_target, [sample_attack_llm01], system_prompt=SYSTEM_PROMPT, api_key="sk-test"
        )
        assert scanner._client is None
        await scanner.cleanup()  # should not raise
        assert scanner._client is None
