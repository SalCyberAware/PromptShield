"""Pytest configuration and shared fixtures for the PromptShield backend tests."""
import pytest

_PROVIDER_ENV_VARS = (
    "OPENAI_API_KEY",
    "PROMPTSHIELD_ANALYZER_OPENAI_KEY",
    "PROMPTSHIELD_TARGET_OPENAI_KEY",
    "ANTHROPIC_API_KEY",
    "PROMPTSHIELD_ANALYZER_ANTHROPIC_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GENAI_API_KEY",
    "PROMPTSHIELD_ANALYZER_GEMINI_KEY",
    "OLLAMA_HOST",
    "PROMPTSHIELD_ANALYZER_OLLAMA_HOST",
    "FRONTEND_URL",
    "PROMPTSHIELD_WEB_ENSEMBLE",
)


@pytest.fixture(autouse=True)
def _clear_provider_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip provider keys + FRONTEND_URL so the health payload is deterministic.

    A developer's real keys would otherwise flip the providers readiness map.
    Tests that need a key present set it explicitly via ``monkeypatch.setenv``.
    """
    for var in _PROVIDER_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _fresh_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give each test a fresh limiter so per-IP/daily state never leaks across tests.

    Limit-specific tests replace ``main.limiter`` with their own configured one.
    """
    import limits
    import main

    monkeypatch.setattr(main, "limiter", limits.Limiter())
