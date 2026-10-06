"""Tests for the web hardening layer in main.py.

Covers the security headers, the production switches (docs off, CORS narrowed,
no credentials), the schema and body size limits, and the generic client error
whose detail stays in a redacted server log line.
"""
from __future__ import annotations

import logging

import main
import pytest
from fastapi.testclient import TestClient
from main import (
    GENERIC_SCAN_ERROR,
    MAX_REQUEST_BODY_BYTES,
    MAX_SYSTEM_PROMPT_CHARS,
    SECURITY_HEADERS,
    create_app,
    is_production,
)

FRONTEND = "https://frontend.example"


@pytest.fixture
def dev_client() -> TestClient:
    return TestClient(create_app(production=False))


@pytest.fixture
def prod_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("FRONTEND_URL", FRONTEND)
    return TestClient(create_app(production=True))


# ── Security headers ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("production", [False, True])
def test_security_headers_on_health(production: bool) -> None:
    response = TestClient(create_app(production=production)).get("/api/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["strict-transport-security"].startswith("max-age=")


def test_security_headers_on_error_and_stream(
    dev_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom(system_prompt: str, on_progress=None):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "run_web_scan", _boom)

    not_found = dev_client.get("/no-such-route")
    stream = dev_client.post("/api/scan/stream", json={"system_prompt": "x"})

    for response in (not_found, stream):
        for name, value in SECURITY_HEADERS.items():
            assert response.headers[name] == value


# ── Production switches ───────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_are_off_in_production(prod_client: TestClient, path: str) -> None:
    assert prod_client.get(path).status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_stay_on_in_development(dev_client: TestClient, path: str) -> None:
    assert dev_client.get(path).status_code == 200


def test_production_cors_allows_frontend_without_credentials(
    prod_client: TestClient,
) -> None:
    response = prod_client.options(
        "/api/scan/stream",
        headers={"Origin": FRONTEND, "Access-Control-Request-Method": "POST"},
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FRONTEND
    assert "access-control-allow-credentials" not in response.headers


@pytest.mark.parametrize(
    "origin", ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]
)
def test_production_cors_rejects_localhost(prod_client: TestClient, origin: str) -> None:
    response = prod_client.options(
        "/api/scan/stream",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )

    assert "access-control-allow-origin" not in response.headers


def test_development_cors_still_allows_localhost(dev_client: TestClient) -> None:
    response = dev_client.options(
        "/api/scan/stream",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        (None, True),
        ("", True),
        ("production", True),
        ("staging", True),
        ("develop", True),
        ("development", False),
        (" Development ", False),
    ],
)
def test_is_production_defaults_to_production(
    monkeypatch: pytest.MonkeyPatch, env: str | None, expected: bool
) -> None:
    if env is not None:
        monkeypatch.setenv("PROMPTSHIELD_ENV", env)

    assert is_production() is expected


def test_railway_environment_name_does_not_turn_on_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "staging")

    assert is_production() is True


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_default_app_has_docs_off(path: str) -> None:
    assert TestClient(create_app()).get(path).status_code == 404


def test_default_app_rejects_localhost_cors() -> None:
    response = TestClient(create_app()).options(
        "/api/scan/stream",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_development_flag_turns_docs_on(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.setenv("PROMPTSHIELD_ENV", "development")

    assert TestClient(create_app()).get(path).status_code == 200


# ── Size limits ───────────────────────────────────────────────────────────────


def test_system_prompt_over_schema_ceiling_is_422(dev_client: TestClient) -> None:
    response = dev_client.post(
        "/api/scan/stream", json={"system_prompt": "a" * (MAX_SYSTEM_PROMPT_CHARS + 1)}
    )

    assert response.status_code == 422


def test_oversized_body_is_413(dev_client: TestClient) -> None:
    response = dev_client.post(
        "/api/scan/stream",
        content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.headers["x-frame-options"] == "DENY"


def test_oversized_chunked_body_is_413(dev_client: TestClient) -> None:
    def chunks():  # type: ignore[no-untyped-def]
        for _ in range(5):
            yield b"x" * (MAX_REQUEST_BODY_BYTES // 4)

    response = dev_client.post(
        "/api/scan/stream",
        content=chunks(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413


def test_schema_ceiling_fits_inside_body_limit() -> None:
    # A maximal prompt with every character JSON-escaped must still fit.
    assert MAX_SYSTEM_PROMPT_CHARS * 6 + 64 <= MAX_REQUEST_BODY_BYTES


# ── Generic client error, redacted server log ─────────────────────────────────


def test_scan_error_is_generic_and_log_is_redacted(
    dev_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    key = "sk-test-not-a-real-key-123456"
    prompt = "SECRET-SYSTEM-PROMPT-MARKER"
    monkeypatch.setenv("OPENAI_API_KEY", key)

    async def _boom(system_prompt: str, on_progress=None):  # type: ignore[no-untyped-def]
        raise RuntimeError(
            f"provider rejected key {key} for prompt {system_prompt}; "
            "also saw sk-otherkeyshape99999"
        )

    monkeypatch.setattr(main, "run_web_scan", _boom)

    with caplog.at_level(logging.ERROR, logger="promptshield.web"):
        response = dev_client.post("/api/scan/stream", json={"system_prompt": prompt})

    assert GENERIC_SCAN_ERROR in response.text
    assert "provider rejected" not in response.text
    assert key not in response.text

    records = [r for r in caplog.records if r.name == "promptshield.web"]
    assert len(records) == 1
    logged = records[0].getMessage()
    assert "RuntimeError" in logged
    assert "provider rejected key" in logged
    assert key not in logged
    assert prompt not in logged
    assert "sk-otherkeyshape99999" not in logged
