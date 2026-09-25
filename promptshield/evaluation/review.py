"""Turning a machine-proposed label into a human-confirmed one.

The decision logic lives here rather than in the click command so it can be
tested without a terminal: what order cases come in, what a confirm or a change
does to a case, and how an edited case goes back into the benchmark.

What a decision records, and why each part is there:

``review_status``
    ``REVIEWED``. This is the flag the runner and the CI baseline key off — an
    unreviewed label is a candidate, and scoring a judge against candidates its
    own sibling produced measures agreement, not accuracy.

``proposed_by``
    Flips to ``human`` only when the verdict actually changes. A confirmed
    machine proposal is a different thing from a human-authored label, and the
    pair (``REVIEWED``, ``machine``) says exactly that: a person read it and the
    machine had it right. Collapsing the two would throw away the one statistic
    that says how good the candidate labels were.

``review``
    Who, when, what they did, and — on a change — the verdict and rationale that
    were replaced. Nothing a reviewer overrides is deleted; it moves.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from .benchmark import VERDICTS, Benchmark, BenchmarkCase

#: Review order. Vulnerable first: they are the smallest class, they are what
#: recall is computed from, and a wrong one costs more than a wrong held. The
#: held majority is mostly refusals, which read fast once the eye is in.
REVIEW_ORDER: tuple[str, ...] = ("vulnerable", "needs_review", "held")

#: A change has to say why in at least this many characters. Same floor the
#: benchmark loader puts on any rationale: a label nobody can evaluate is worse
#: than no label, and "wrong" is not a reason.
MIN_REASON_CHARS = 15


class ReviewError(ValueError):
    """A decision that cannot be recorded, with a reviewer-facing message."""


def review_queue(
    benchmark: Benchmark, only: list[str] | None = None
) -> tuple[BenchmarkCase, ...]:
    """The cases to show, in the order they should be shown.

    By default, the unreviewed cases, vulnerable first. With ``only``, exactly
    those case ids in the order given, whether or not they were reviewed
    already -- the way to re-open a label without hand-editing the file. An id
    that is not in the benchmark is an error rather than silently skipped.
    """
    if only:
        by_id = {case.id: case for case in benchmark.cases}
        missing = [case_id for case_id in only if case_id not in by_id]
        if missing:
            raise ReviewError(f"not in this benchmark: {', '.join(missing)}")
        return tuple(by_id[case_id] for case_id in dict.fromkeys(only))

    order = {verdict: index for index, verdict in enumerate(REVIEW_ORDER)}
    return tuple(
        sorted(
            benchmark.unreviewed(),
            key=lambda case: (order.get(case.verdict, len(order)), case.id),
        )
    )


def queue_summary(benchmark: Benchmark) -> dict[str, int]:
    """How many unreviewed cases of each verdict remain, in review order."""
    counts = {verdict: 0 for verdict in REVIEW_ORDER}
    for case in benchmark.unreviewed():
        counts[case.verdict] = counts.get(case.verdict, 0) + 1
    return counts


def default_reviewer() -> str:
    """Best guess at who is reviewing: git identity, else the OS user."""
    try:
        result = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        name = result.stdout.strip()
        if name:
            return name
    except (OSError, subprocess.SubprocessError):
        pass
    return os.getenv("USER") or os.getenv("USERNAME") or "unknown"


def _stamp(
    case: BenchmarkCase, reviewer: str, action: str, now: datetime | None = None
) -> dict[str, Any]:
    stamp: dict[str, Any] = {
        "action": action,
        "reviewer": reviewer,
        "reviewed_at": (now or datetime.now(UTC)).isoformat(),
    }
    # A re-opened case keeps the decision it replaces: nothing a reviewer
    # overrides is deleted, including an earlier review.
    if case.review:
        stamp["previous_review"] = dict(case.review)
    return stamp


def confirm_case(
    case: BenchmarkCase, reviewer: str, now: datetime | None = None
) -> BenchmarkCase:
    """Accept the proposed label as correct.

    Verdict and rationale are left exactly as they were: the machine's reasoning
    is what the reviewer agreed with, so rewriting it in the reviewer's words
    would misattribute it.
    """
    return replace(
        case,
        review_status="REVIEWED",
        review=_stamp(case, reviewer, "confirmed", now),
    )


def change_case(
    case: BenchmarkCase,
    verdict: str,
    reason: str,
    reviewer: str,
    now: datetime | None = None,
) -> BenchmarkCase:
    """Replace the proposed label with the reviewer's, and say why."""
    if verdict not in VERDICTS:
        raise ReviewError(f"{verdict!r} is not one of {', '.join(VERDICTS)}")
    if verdict == case.verdict:
        raise ReviewError(
            f"{case.id} is already labeled {verdict!r} — confirm it instead of changing it"
        )
    cleaned = reason.strip()
    if len(cleaned) < MIN_REASON_CHARS:
        raise ReviewError(
            f"a reason needs at least {MIN_REASON_CHARS} characters to be worth "
            f"reading later (got {len(cleaned)})"
        )

    stamp = _stamp(case, reviewer, "changed", now)
    stamp["previous_verdict"] = case.verdict
    stamp["superseded_rationale"] = case.rationale
    return replace(
        case,
        verdict=verdict,
        rationale=cleaned,
        review_status="REVIEWED",
        proposed_by="human",
        review=stamp,
    )


def apply_decision(benchmark: Benchmark, decided: BenchmarkCase) -> Benchmark:
    """Put an edited case back, keeping every other case and the file order."""
    if not any(case.id == decided.id for case in benchmark.cases):
        raise ReviewError(f"{decided.id} is not in this benchmark")
    return replace(
        benchmark,
        cases=tuple(decided if case.id == decided.id else case for case in benchmark.cases),
    )
