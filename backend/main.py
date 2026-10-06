"""PromptShield web backend — FastAPI app.

Thin web wrapper around the ``promptshield`` package (imported as a library).
Exposes ``/api/health`` and the streaming ``POST /api/scan/stream`` scan endpoint.
Abuse controls (length cap, per-IP rate limit, daily cap) gate the scan endpoint
before any model call; see ``limits.py``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections.abc import AsyncIterator

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from limits import LimitRejectedError, build_limiter
from pydantic import BaseModel, Field
from scan import (
    WEB_DEMO_ATTACK_IDS,
    run_ensemble_judging,
    run_web_scan,
    serialize_scan_result,
    web_ensemble_enabled,
)
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from promptshield import __version__ as promptshield_version
from promptshield.models import Attack

load_dotenv()

# Single shared limiter for this instance. In-memory state; see limits.py.
limiter = build_limiter()

logger = logging.getLogger("promptshield.web")

# Hard schema ceiling on the submitted prompt. The configurable, friendlier cap
# (PROMPTSHIELD_WEB_MAX_PROMPT_CHARS, default 8000) lives in limits.py and
# answers normal oversize prompts with a clear 400; this bound only stops a
# pathological payload from being parsed into a model at all, so it sits well
# above any sensible setting of that cap.
MAX_SYSTEM_PROMPT_CHARS = 32_000

# Request body ceiling, in bytes. JSON can escape one character into six
# (\uXXXX), so this leaves room for a maximal prompt and little else.
MAX_REQUEST_BODY_BYTES = 256 * 1024

# Sent on every response. Browsers ignore HSTS over plain HTTP, so it is
# harmless in local development.
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}

GENERIC_SCAN_ERROR = "The scan could not be completed. Please try again later."

# Local dev origins. Allowed outside production only.
_DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]


def is_production() -> bool:
    """Whether this process is the deployed production service.

    ``PROMPTSHIELD_ENV`` is an explicit override (``production`` or anything
    else). Without it, Railway's ``RAILWAY_ENVIRONMENT_NAME`` decides, which
    Railway sets on every deployment. Neither is set in local development or
    tests, so those default to non-production.
    """
    explicit = os.getenv("PROMPTSHIELD_ENV")
    if explicit:
        return explicit.strip().lower() == "production"
    return os.getenv("RAILWAY_ENVIRONMENT_NAME", "").strip().lower() == "production"


def cors_origins(production: bool) -> list[str]:
    """CORS allowlist: the deployed frontend, plus localhost outside production."""
    frontend_url = os.getenv("FRONTEND_URL")
    deployed = [frontend_url] if frontend_url else []
    return deployed if production else [*_DEV_ORIGINS, *deployed]


class SecurityHeadersMiddleware:
    """Add :data:`SECURITY_HEADERS` to every HTTP response, streaming ones included."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in SECURITY_HEADERS.items():
                    key = name.lower().encode()
                    if key not in present:
                        headers.append((key, value.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware:
    """Reject request bodies over ``max_bytes`` with 413 before they are parsed.

    Checks ``Content-Length`` up front, and also counts bytes as they arrive so
    a chunked body without a declared length cannot slip past.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send: Send) -> None:
        body = json.dumps({"detail": "Request body too large."}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = 0
                if declared > self.max_bytes:
                    await self._reject(send)
                    return

        received = 0
        response_started = False
        rejected = False

        # FastAPI turns any exception raised while reading the body into a 400,
        # so on overflow this answers 413 itself, then reports a disconnect to
        # stop the app reading and drops whatever the app tries to send after.
        async def limited_receive() -> Message:
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    rejected = True
                    if not response_started:
                        await self._reject(send)
                    return {"type": "http.disconnect"}
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if rejected:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        await self.app(scope, limited_receive, tracking_send)


# Shapes of provider credentials, in case an exception message echoes one back.
_KEY_SHAPES = re.compile(r"(sk-[A-Za-z0-9_\-]{8,}|AIza[A-Za-z0-9_\-]{20,})")
_SECRET_ENV_VARS = (
    "OPENAI_API_KEY",
    "PROMPTSHIELD_ANALYZER_OPENAI_KEY",
    "PROMPTSHIELD_TARGET_OPENAI_KEY",
    "ANTHROPIC_API_KEY",
    "PROMPTSHIELD_ANALYZER_ANTHROPIC_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GENAI_API_KEY",
    "PROMPTSHIELD_ANALYZER_GEMINI_KEY",
)
_MAX_LOGGED_DETAIL = 300


def _redacted_detail(exc: BaseException, system_prompt: str) -> str:
    """The exception message, made safe for a server log.

    Removes the submitted prompt and every configured key value, masks anything
    shaped like a provider key, and bounds the length.
    """
    detail = str(exc)
    for secret in [system_prompt, *(os.getenv(name) for name in _SECRET_ENV_VARS)]:
        if secret:
            detail = detail.replace(secret, "[redacted]")
    detail = _KEY_SHAPES.sub("[redacted]", detail)
    return detail[:_MAX_LOGGED_DETAIL]


router = APIRouter()


def _provider_readiness() -> dict[str, bool]:
    """Report which server-side providers are configured — booleans only.

    Mirrors the engine's key precedence (analyzer + target env vars). NEVER
    returns key values; only whether a usable credential/host is present.
    """

    def _any_set(*names: str) -> bool:
        return any(os.getenv(name) for name in names)

    return {
        "openai": _any_set(
            "OPENAI_API_KEY",
            "PROMPTSHIELD_ANALYZER_OPENAI_KEY",
            "PROMPTSHIELD_TARGET_OPENAI_KEY",
        ),
        "anthropic": _any_set(
            "ANTHROPIC_API_KEY",
            "PROMPTSHIELD_ANALYZER_ANTHROPIC_KEY",
        ),
        "gemini": _any_set(
            "GOOGLE_API_KEY",
            "GOOGLE_GENAI_API_KEY",
            "PROMPTSHIELD_ANALYZER_GEMINI_KEY",
        ),
        "ollama": _any_set(
            "OLLAMA_HOST",
            "PROMPTSHIELD_ANALYZER_OLLAMA_HOST",
        ),
    }


def _build_commit() -> str:
    """The git commit this process is actually running.

    Railway sets ``RAILWAY_GIT_COMMIT_SHA`` on every deployment that originates
    from a GitHub push, and exposes it to the running container as well as the
    build. ``GIT_COMMIT_SHA`` is a platform-neutral override for anywhere that
    is not Railway. Neither is set during local development, which is what
    ``"unknown"`` means; it is not an error condition.

    Read per request rather than captured at import so that tests can vary it.
    The value is fixed for the lifetime of a deployed process either way.
    """
    return (
        os.getenv("RAILWAY_GIT_COMMIT_SHA")
        or os.getenv("GIT_COMMIT_SHA")
        or "unknown"
    )


@router.get("/api/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": "PromptShield API",
        "version": promptshield_version,
        # Build identity: lets a post-deploy check prove the running build is
        # the commit that was just pushed. See docs/AUTOMATION_PLAN.md.
        "commit": _build_commit(),
        "providers": _provider_readiness(),
    }


class ScanRequest(BaseModel):
    """Request body for the streaming scan endpoint."""

    system_prompt: str = Field(max_length=MAX_SYSTEM_PROMPT_CHARS)


def _sse(event: dict[str, object]) -> str:
    """Format one event as an SSE ``data:`` frame (type carried inside the JSON)."""
    return f"data: {json.dumps(event)}\n\n"


async def _scan_event_stream(system_prompt: str) -> AsyncIterator[str]:
    """Yield SSE frames for a single scan: start → progress* → (done | error).

    Bridges ``run_web_scan``'s synchronous ``on_progress`` callback to the stream
    via an ``asyncio.Queue``: the callback enqueues progress events while the scan
    runs as a background task. The task always enqueues a terminal ``done`` or
    ``error`` event followed by a ``None`` sentinel, so the drain loop below
    terminates and the stream closes cleanly even when the scan raises — it never
    hangs. Everything runs on one event loop, so ``put_nowait`` is safe.
    """
    queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue()

    def on_progress(current: int, total: int, attack: Attack) -> None:
        queue.put_nowait(
            {
                "type": "progress",
                "current": current,
                "total": total,
                "attack_id": attack.id,
                "owasp_category": attack.owasp_category,
            }
        )

    async def _run() -> None:
        try:
            scan = await run_web_scan(system_prompt, on_progress)
            if web_ensemble_enabled():
                ensemble = await run_ensemble_judging(scan)
                result = serialize_scan_result(
                    scan, ensemble_verdicts=ensemble, system_prompt=system_prompt
                )
            else:
                result = serialize_scan_result(scan, system_prompt=system_prompt)
            queue.put_nowait({"type": "done", "result": result})
        except Exception as exc:  # noqa: BLE001 - surfaced to the client as an error event
            # The client gets a fixed message; the detail stays in the server
            # log, redacted so it never carries the prompt or a key.
            logger.error(
                "scan failed: %s: %s",
                type(exc).__name__,
                _redacted_detail(exc, system_prompt),
            )
            queue.put_nowait({"type": "error", "message": GENERIC_SCAN_ERROR})
        finally:
            queue.put_nowait(None)

    task = asyncio.create_task(_run())
    try:
        yield _sse({"type": "start", "total": len(WEB_DEMO_ATTACK_IDS)})
        while True:
            event = await queue.get()
            if event is None:
                break
            yield _sse(event)
    finally:
        # Surface/clean up the task (already finished on the normal path).
        await task


def _client_ip(request: Request) -> str:
    """Resolve the client IP behind a proxy.

    Behind Railway's proxy the real client is the leftmost entry of
    ``X-Forwarded-For``; this trusts the platform to set and sanitize that header.
    Falls back to the direct socket peer for local/dev use.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/api/scan/stream")
async def scan_stream(payload: ScanRequest, request: Request) -> StreamingResponse:
    """Run the web-demo scan against the submitted system prompt, streaming SSE.

    Abuse controls run here, before the stream starts, so a rejected request never
    reaches a target or judge call and is returned as a clean HTTP error.
    """
    try:
        limiter.check_and_consume(payload.system_prompt, _client_ip(request))
    except LimitRejectedError as rejected:
        raise HTTPException(
            status_code=rejected.status_code,
            detail=rejected.message,
            headers=rejected.headers,
        ) from rejected

    return StreamingResponse(
        _scan_event_stream(payload.system_prompt),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def create_app(production: bool | None = None) -> FastAPI:
    """Build the API. ``production`` defaults to :func:`is_production`.

    Production turns off the interactive docs and the OpenAPI schema, narrows
    CORS to the deployed frontend, and sends no credentials over CORS.
    """
    if production is None:
        production = is_production()

    application = FastAPI(
        title="PromptShield API",
        description="Scan a system prompt against the OWASP LLM Top 10, a web wrapper around the PromptShield engine.",
        version=promptshield_version,
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )
    application.include_router(router)

    # Middleware added last runs first: the security headers wrap everything,
    # so a 413 from the body limit and CORS preflight replies carry them too.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins(production),
        allow_credentials=not production,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.add_middleware(BodySizeLimitMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)
    return application


app = create_app()
