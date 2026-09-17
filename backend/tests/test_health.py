"""API-level tests for GET /api/health.

Drives the FastAPI app through TestClient. The autouse ``_clear_provider_env_vars``
fixture in backend/conftest.py keeps the providers readiness map deterministic.
"""
import pytest
from fastapi.testclient import TestClient
from main import app

from promptshield import __version__ as promptshield_version


@pytest.fixture
def client() -> TestClient:
    """A TestClient bound to the real FastAPI app."""
    return TestClient(app)


def test_health_returns_ok_payload(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "PromptShield API"
    assert body["version"] == promptshield_version


def test_health_reports_provider_readiness_shape(client: TestClient) -> None:
    """Providers map exposes the four providers as booleans (no key values)."""
    body = client.get("/api/health").json()
    providers = body["providers"]

    assert set(providers) == {"openai", "anthropic", "gemini", "ollama"}
    assert all(isinstance(v, bool) for v in providers.values())
    # Env cleared by the autouse fixture -> nothing configured.
    assert providers == {
        "openai": False,
        "anthropic": False,
        "gemini": False,
        "ollama": False,
    }


def test_health_reflects_configured_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A configured key flips its provider to True — and only a boolean leaks."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-a-real-key")

    providers = client.get("/api/health").json()["providers"]

    assert providers["openai"] is True
    assert providers["anthropic"] is False
    # The secret value must never appear anywhere in the response.
    assert "sk-not-a-real-key" not in client.get("/api/health").text


# ── Build identity ───────────────────────────────────────────────────────────


def test_health_reports_unknown_commit_when_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Local development, where no platform variable is set, still works."""
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    monkeypatch.delenv("GIT_COMMIT_SHA", raising=False)

    assert client.get("/api/health").json()["commit"] == "unknown"


def test_health_reports_railway_commit_sha(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Railway the deployed commit is reported verbatim."""
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "a" * 40)

    assert client.get("/api/health").json()["commit"] == "a" * 40


def test_health_commit_falls_back_to_platform_neutral_override(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GIT_COMMIT_SHA covers hosts that are not Railway; Railway's wins."""
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    monkeypatch.setenv("GIT_COMMIT_SHA", "b" * 40)
    assert client.get("/api/health").json()["commit"] == "b" * 40

    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "c" * 40)
    assert client.get("/api/health").json()["commit"] == "c" * 40


def test_health_keeps_existing_fields_alongside_commit(client: TestClient) -> None:
    """The uptime monitor reads status/service/version — adding commit is additive."""
    body = client.get("/api/health").json()

    assert set(body) == {"status", "service", "version", "commit", "providers"}
