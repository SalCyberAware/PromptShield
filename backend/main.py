"""PromptShield web backend — FastAPI app.

Thin web wrapper around the ``promptshield`` package (imported as a library).
Exposes ``/api/health`` and the streaming ``POST /api/scan/stream`` scan endpoint.
Abuse controls (rate limiting, length cap, budget cap) land in a later slice.
"""
from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from scan import WEB_DEMO_ATTACK_IDS, run_web_scan, serialize_scan_result

from promptshield import __version__ as promptshield_version
from promptshield.models import Attack

load_dotenv()

app = FastAPI(
    title="PromptShield API",
    description="Scan a system prompt against the OWASP LLM Top 10 — web wrapper around the PromptShield engine.",
    version=promptshield_version,
)

# CORS: always allow local dev origins; add the deployed frontend when FRONTEND_URL is set.
_DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]
FRONTEND_URL = os.getenv("FRONTEND_URL")
allow_origins = [*_DEV_ORIGINS, FRONTEND_URL] if FRONTEND_URL else _DEV_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/api/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": "PromptShield API",
        "version": promptshield_version,
        "providers": _provider_readiness(),
    }


class ScanRequest(BaseModel):
    """Request body for the streaming scan endpoint."""

    system_prompt: str


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
            queue.put_nowait({"type": "done", "result": serialize_scan_result(scan)})
        except Exception as exc:  # noqa: BLE001 - surfaced to the client as an error event
            queue.put_nowait({"type": "error", "message": str(exc)})
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


@app.post("/api/scan/stream")
async def scan_stream(request: ScanRequest) -> StreamingResponse:
    """Run the web-demo scan against the submitted system prompt, streaming SSE."""
    return StreamingResponse(
        _scan_event_stream(request.system_prompt),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
