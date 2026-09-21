"""The recorded accuracy baseline that CI gates on.

A baseline is only meaningful next to what produced it, so the file records the
run's full provenance — judge, judge model, benchmark version, attack library
version, PromptShield version — not just a number. A baseline recorded against
a different benchmark version is refused rather than silently compared, because
"accuracy fell" and "the benchmark changed" are different events and only one of
them is a regression.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_BASELINE_PATH = Path(__file__).parent / "data" / "baseline.json"

#: Floating-point slack. Accuracy is a ratio of small integers here, so this is
#: only guarding representation error, not allowing real drift.
TOLERANCE = 1e-9


class BaselineError(ValueError):
    """No baseline recorded, or it cannot be compared to this run."""


@dataclass(frozen=True)
class BaselineVerdict:
    passed: bool
    message: str
    baseline_accuracy: float
    run_accuracy: float


def write_baseline(report: Any, path: Path | str | None = None) -> Path:
    """Record a run's accuracy and provenance as the new baseline."""
    out = Path(path) if path is not None else DEFAULT_BASELINE_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "accuracy": report.metrics.accuracy,
        "correct": report.metrics.correct,
        "total": report.metrics.total,
        "per_class": {
            entry.verdict: {
                "precision": entry.precision,
                "recall": entry.recall,
                "support": entry.support,
            }
            for entry in report.metrics.per_class
        },
        "provenance": dict(report.provenance),
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return out


def load_baseline(path: Path | str | None = None) -> dict[str, Any]:
    resolved = Path(path) if path is not None else DEFAULT_BASELINE_PATH
    if not resolved.exists():
        raise BaselineError(
            f"no baseline recorded at {resolved}. Run the harness once with "
            "--write-baseline to establish one."
        )
    with open(resolved, encoding="utf-8") as handle:
        return dict(json.load(handle))


def compare_to_baseline(report: Any, baseline: dict[str, Any]) -> BaselineVerdict:
    """Decide whether a run regressed against the baseline.

    Refuses the comparison outright when the benchmark version or the judge
    differs, rather than reporting a meaningless delta. Changing either is a
    legitimate thing to do — it just means the old number no longer describes
    the same measurement, and the baseline has to be re-recorded deliberately.
    """
    run = report.provenance
    recorded = baseline.get("provenance", {})

    for field, label in (("benchmark_version", "benchmark"), ("judge", "judge")):
        if recorded.get(field) and run.get(field) != recorded.get(field):
            raise BaselineError(
                f"baseline was recorded against {label} "
                f"{recorded.get(field)!r} but this run used {run.get(field)!r}. "
                "Re-record the baseline deliberately rather than comparing across "
                "different measurements."
            )

    baseline_accuracy = float(baseline.get("accuracy", 0.0))
    run_accuracy = float(report.metrics.accuracy)

    if run_accuracy + TOLERANCE < baseline_accuracy:
        drop = baseline_accuracy - run_accuracy
        return BaselineVerdict(
            passed=False,
            message=(
                f"[red]REGRESSION[/red]: accuracy {run_accuracy:.3f} is below the "
                f"baseline {baseline_accuracy:.3f} (down {drop:.3f}). "
                "Inspect the disagreements above."
            ),
            baseline_accuracy=baseline_accuracy,
            run_accuracy=run_accuracy,
        )

    if run_accuracy > baseline_accuracy + TOLERANCE:
        gain = run_accuracy - baseline_accuracy
        return BaselineVerdict(
            passed=True,
            message=(
                f"[green]IMPROVED[/green]: accuracy {run_accuracy:.3f} is above the "
                f"baseline {baseline_accuracy:.3f} (up {gain:.3f}). "
                "Re-record with --write-baseline to lock the gain in."
            ),
            baseline_accuracy=baseline_accuracy,
            run_accuracy=run_accuracy,
        )

    return BaselineVerdict(
        passed=True,
        message=f"[green]OK[/green]: accuracy {run_accuracy:.3f} holds the baseline.",
        baseline_accuracy=baseline_accuracy,
        run_accuracy=run_accuracy,
    )
