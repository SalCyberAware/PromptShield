"""Scan orchestration service for the PromptShield web demo.

Wires the engine's ``SystemPromptScanner`` to the locked Phase 0 decisions
(see ``docs/WEB_ARCHITECTURE.md``):

- **Decision 1** — a trimmed 13-attack web-demo set (the other 37 of the 50 stay
  in the CLI), pinned here as an explicit ID allowlist.
- **Decision 2** — a ``gpt-4o-mini`` target plus a trimmed 2-tier cross-provider
  analyzer cascade (Claude Sonnet → Gemini Flash) on top of the always-on
  pattern floor. Model tiers are env-configurable, defaulting conservative.

This module is pure orchestration: no HTTP, no SSE, no rate limiting / length cap
/ budget cap (those are later slices). Importing it is side-effect-free — no
network clients are created until :func:`run_web_scan` is awaited. The
``on_progress(current, total, attack)`` callback is passed straight through to
``run_scan``; it is the seam the SSE layer plugs into next.
"""
from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from typing import Any

from promptshield.attacks.library import AttackLibrary
from promptshield.engines.system_prompt_scanner import (
    SystemPromptScanner,
    default_target_model,
    internal_target_url,
)
from promptshield.models import Attack, Scan, TargetConfig, TargetType

# ── Decision 1: the 13 web-demo attacks (explicit allowlist) ────────────────────
# The full 50 stays in the CLI. Order here is the visitor-facing run order.
WEB_DEMO_ATTACK_IDS: tuple[str, ...] = (
    "PS-LLM01-001",   # Direct instruction override
    "PS-LLM01-009",   # Prompt leaking via repetition
    "PS-LLM01-002",   # DAN jailbreak
    "PS-LLM01-004",   # Encoding bypass (base64)
    "PS-LLM01-008",   # Authority impersonation
    "PS-CUSTOM-001",  # Token-boundary confusion
    "PS-CUSTOM-003",  # Adversarial suffix (GCG)
    "PS-LLM06-001",   # System prompt extraction
    "PS-CUSTOM-004",  # Memory confabulation
    "PS-LLM09-002",   # Medical advice without disclaimer
    "PS-LLM10-001",   # Model fingerprinting
    "PS-LLM08-002",   # Privilege escalation
    "PS-LLM02-001",   # XSS payload generation
)

# ── Decision 2: analyzer tiers (env-configurable, conservative defaults) ────────
# ClaudeAnalyzer has no env-based model override of its own, so the Sonnet tier is
# resolved here. GeminiAnalyzer already defaults to Flash (gemini-2.0-flash-001).
_ANTHROPIC_MODEL_ENV = "PROMPTSHIELD_ANALYZER_ANTHROPIC_MODEL"
DEFAULT_ANALYZER_ANTHROPIC_MODEL = "claude-sonnet-4-6"

# run_scan sleeps 60/rate_limit between attacks. The target runs on our own key,
# so no external courtesy throttle is needed here; real per-IP/budget limiting is
# the abuse-control slice. 60 rpm => a 1s pacing gap between attacks.
_WEB_RATE_LIMIT = 60


def analyzer_anthropic_model() -> str:
    """Resolve the Claude (Sonnet-tier) analyzer model — env override, else default."""
    return os.getenv(_ANTHROPIC_MODEL_ENV) or DEFAULT_ANALYZER_ANTHROPIC_MODEL


def load_web_demo_attacks() -> list[Attack]:
    """Load the 13 web-demo attacks by ID, preserving ``WEB_DEMO_ATTACK_IDS`` order.

    Raises ``ValueError`` naming every missing ID, so a renamed/removed attack
    fails loudly here instead of silently shrinking the demo set.
    """
    library = AttackLibrary()
    resolved: list[Attack] = []
    missing: list[str] = []
    for attack_id in WEB_DEMO_ATTACK_IDS:
        attack = library.get(attack_id)
        if attack is None:
            missing.append(attack_id)
        else:
            resolved.append(attack)

    if missing:
        raise ValueError(
            "Web-demo attack set is out of sync with the attack library; "
            "missing IDs: " + ", ".join(missing)
        )
    return resolved


def build_web_analyzers() -> list[Any]:
    """Build Decision 2's trimmed cascade in priority order: [Claude Sonnet, Gemini Flash].

    ``run_scan`` walks the list and keeps the first usable verdict, so order =
    Claude (primary) → Gemini (fallback). An analyzer whose provider key/SDK is
    absent (``ValueError``/``ImportError``) is skipped, degrading to the pattern
    floor rather than failing the whole scan. This is deliberately **not** the
    engine's default 4-tier cascade — no OpenAI, no Ollama.
    """
    from promptshield.analyzers.claude_analyzer import ClaudeAnalyzer
    from promptshield.analyzers.gemini_analyzer import GeminiAnalyzer

    factories: tuple[Callable[[], Any], ...] = (
        lambda: ClaudeAnalyzer(model=analyzer_anthropic_model()),
        lambda: GeminiAnalyzer(),  # default model => Flash
    )

    analyzers: list[Any] = []
    for make in factories:
        try:
            analyzers.append(make())
        except (ValueError, ImportError):
            # Provider key/SDK missing: skip this tier, keep the pattern floor.
            continue
    return analyzers


async def run_web_scan(
    system_prompt: str,
    on_progress: Callable[[int, int, Attack], None] | None = None,
) -> Scan:
    """Run the trimmed web-demo scan against a visitor-supplied system prompt.

    Fires the 13-attack set at ``system_prompt`` via a server-side target model
    (``gpt-4o-mini``, overridable with ``PROMPTSHIELD_TARGET_MODEL``), judging
    each reply with the pattern floor + the trimmed [Sonnet, Gemini] cascade.
    ``on_progress`` is forwarded verbatim to ``run_scan`` (the SSE seam). Returns
    the aggregated :class:`~promptshield.models.Scan`.
    """
    attacks = load_web_demo_attacks()
    target_model = default_target_model()
    target = TargetConfig(
        url=internal_target_url(target_model),
        target_type=TargetType.SYSTEM_PROMPT,
        rate_limit=_WEB_RATE_LIMIT,
    )
    scanner = SystemPromptScanner(
        target,
        attacks,
        system_prompt=system_prompt,
        model=target_model,
    )
    return await scanner.run_scan(
        scan_id=f"web-{uuid.uuid4().hex[:12]}",
        on_progress=on_progress,
        analyzers=build_web_analyzers(),
    )
