"""PromptShield web backend — FastAPI app.

Thin web wrapper around the ``promptshield`` package (imported as a library).
This slice is the scaffold + health check only; the SSE scan endpoint, rate
limiting, and the trimmed web attack set land in a later slice.
"""
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from promptshield import __version__ as promptshield_version

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
