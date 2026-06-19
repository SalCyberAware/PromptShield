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
from promptshield.models import (
    Attack,
    Confidence,
    Finding,
    Scan,
    TargetConfig,
    TargetType,
    Transcript,
)

_INTERNAL_URL_PREFIX = "internal://"

# ── Result projection vocabulary (slice 3a) ─────────────────────────────────────
# Per-attack status. "error" and "not_ai_judged" must never be counted or shown
# as "held": that is the core honesty rule.
_PATTERN_ANALYZER = "pattern_analyzer"
_RESPONSE_EXCERPT_LIMIT = 600
_TRUNCATION_MARKER = "... [truncated]"
# Statuses that represent an AI-confirmed concern; only these feed the severity
# and OWASP breakdowns.
_FINDING_STATUSES = ("vulnerable", "needs_review")
# Statuses that carry a bounded excerpt of the target reply for the frontend.
_EXCERPT_STATUSES = ("vulnerable", "needs_review", "not_ai_judged")

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


def _make_excerpt(text: str, limit: int = _RESPONSE_EXCERPT_LIMIT) -> str:
    """Return at most ``limit`` chars of ``text``, with a plain truncation marker."""
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + _TRUNCATION_MARKER


def _verdict_entry(
    analyzer: str,
    vulnerable: bool,
    confidence_score: float | None,
    reasoning: str | None,
    errored: bool,
) -> dict[str, Any]:
    """One judge verdict in the ensemble-ready list."""
    return {
        "analyzer": analyzer,
        "vulnerable": vulnerable,
        "confidence_score": confidence_score,
        "reasoning": reasoning,
        "errored": errored,
    }


def _agreement(verdicts: list[dict[str, Any]]) -> str:
    """Agreement across judges: 'single' for 0 or 1 judge, else 'agree'/'disagree'."""
    if len(verdicts) <= 1:
        return "single"
    decisions = {v["vulnerable"] for v in verdicts}
    return "agree" if len(decisions) == 1 else "disagree"


def _build_verdicts(
    status: str, judged_by: str, finding: Finding | None
) -> list[dict[str, Any]]:
    """Build the per-judge verdict list (one entry in single-judge mode).

    A later ensemble slice fills this with multiple entries with no schema change.
    """
    if status in _FINDING_STATUSES and finding is not None:
        ai_verdict = next(
            (v for v in finding.analyzer_verdicts if v.analyzer_name == judged_by),
            None,
        )
        if ai_verdict is not None:
            return [
                _verdict_entry(
                    ai_verdict.analyzer_name,
                    ai_verdict.success,
                    ai_verdict.confidence_score,
                    ai_verdict.reasoning,
                    False,
                )
            ]
        return [_verdict_entry(judged_by, True, finding.confidence_score, None, False)]
    if status == "held":
        # The held verdict's reasoning is not persisted (no finding is created when
        # every judge agrees the prompt defended), so only the decision is known.
        return [_verdict_entry(judged_by, False, None, None, False)]
    return []


def _project_attack(transcript: Transcript, finding: Finding | None) -> dict[str, Any]:
    """Project one attack transcript (plus any finding) into the curated result.

    Status is derived from signals ``run_scan`` already records:
      - a ``[ERROR]``/``[TIMEOUT]`` response prefix means the target call failed,
      - ``analyzers_run`` minus the pattern floor tells us if an AI judge ran,
      - the joined finding tells us whether a judged attack got through.
    """
    response = transcript.response or ""
    errored = response.startswith(("[ERROR]", "[TIMEOUT]"))
    ai_run = [name for name in transcript.analyzers_run if name != _PATTERN_ANALYZER]
    ai_judged = bool(ai_run)

    if errored:
        status = "error"
    elif not ai_judged:
        # Target replied but no AI judge produced a verdict; it fell to the pattern
        # floor. Never counted as held.
        status = "not_ai_judged"
    elif finding is not None:
        low_confidence = (
            finding.needs_manual_review or finding.confidence == Confidence.LOW
        )
        status = "needs_review" if low_confidence else "vulnerable"
    else:
        status = "held"

    if status == "error":
        judged_by = "none"
    elif ai_judged:
        judged_by = ai_run[0]
    else:
        judged_by = _PATTERN_ANALYZER

    is_finding_status = status in _FINDING_STATUSES
    if is_finding_status and finding is not None:
        confidence_score: float | None = finding.confidence_score
        confidence_band: str | None = finding.confidence.value
    else:
        confidence_score = None
        confidence_band = None

    verdicts = _build_verdicts(status, judged_by, finding)

    if status == "vulnerable":
        final_vulnerable: bool | None = True
    elif status == "held":
        final_vulnerable = False
    else:
        final_vulnerable = None

    aggregate = {
        "status": status,
        "agreement": _agreement(verdicts),
        "final_vulnerable": final_vulnerable,
        "final_confidence": confidence_score if is_finding_status else None,
    }

    return {
        "attack_id": transcript.attack_id,
        "name": transcript.attack_name,
        "owasp_category": transcript.owasp_category,
        "severity": transcript.severity.value,
        "payload": transcript.prompt,
        "status": status,
        "ai_judged": ai_judged,
        "judged_by": judged_by,
        "confidence_score": confidence_score,
        "confidence_band": confidence_band,
        "needs_manual_review": finding.needs_manual_review if finding else False,
        "response_excerpt": (
            _make_excerpt(response) if status in _EXCERPT_STATUSES else None
        ),
        "verdicts": verdicts,
        "aggregate": aggregate,
    }


def serialize_scan_result(scan: Scan) -> dict[str, Any]:
    """Project a completed ``Scan`` into the curated, honest payload for ``done``.

    Each attack carries an explicit ``status`` (one of "vulnerable", "held",
    "needs_review", "error", "not_ai_judged") instead of a binary flag, plus its
    provenance, an ensemble-ready ``verdicts`` list, and an ``aggregate``. The
    hard rule: "error" and "not_ai_judged" are never bucketed or shown as "held".

    The payload stays curated and bounded. The only target output included is a
    ``response_excerpt`` capped at ``_RESPONSE_EXCERPT_LIMIT`` chars, populated for
    statuses where the reply is evidence the frontend needs. API keys are never
    part of any field.
    """
    findings_by_attack = {f.attack_id: f for f in scan.findings}

    results: list[dict[str, Any]] = []
    by_status: dict[str, int] = {
        "held": 0,
        "vulnerable": 0,
        "needs_review": 0,
        "error": 0,
        "not_ai_judged": 0,
    }
    by_severity: dict[str, int] = {}
    by_owasp_category: dict[str, int] = {}

    for transcript in scan.transcripts:
        finding = findings_by_attack.get(transcript.attack_id)
        entry = _project_attack(transcript, finding)
        results.append(entry)

        status = entry["status"]
        by_status[status] = by_status.get(status, 0) + 1
        if status in _FINDING_STATUSES:
            by_severity[transcript.severity.value] = (
                by_severity.get(transcript.severity.value, 0) + 1
            )
            by_owasp_category[transcript.owasp_category] = (
                by_owasp_category.get(transcript.owasp_category, 0) + 1
            )

    target_model = scan.target.url.removeprefix(_INTERNAL_URL_PREFIX)

    return {
        "scan_id": scan.scan_id,
        "status": scan.status.value,
        "target_model": target_model,
        "attacks_total": scan.attacks_total,
        "attacks_run": scan.attacks_run,
        "analyzers_used": list(scan.analyzers_used),
        "summary": {
            "target_model": target_model,
            "analyzers_used": list(scan.analyzers_used),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_owasp_category": by_owasp_category,
            # Kept for the existing done headline: only AI-confirmed got-throughs
            # count as failed, only AI-confirmed defenses count as passed. Other
            # statuses are deliberately neither.
            "failed": by_status["vulnerable"],
            "passed": by_status["held"],
        },
        "results": results,
    }
