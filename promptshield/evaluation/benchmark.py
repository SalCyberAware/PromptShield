"""The labeled verdict benchmark: format, loading and validation.

A benchmark case is a frozen (attack, target response, correct verdict) triple.
The point of freezing the response is that a judge can then be scored without
calling a target model at all — the same inputs produce a comparable number on
every run, which is what makes a regression visible.

Design rule: **a case is reviewable on its own.** A person confirming a label
should never have to open the attack library, run the scanner, or ask what
``PS-LLM01-004`` means. So each case denormalizes what it takes to judge it —
the attack's name, what it is attempting, and what counts as success — alongside
the response and the proposed label. The file is a review artifact first and a
test fixture second.

Labels start as ``UNREVIEWED``. A machine-proposed label is a *candidate*, never
ground truth: the runner refuses to score against unreviewed cases unless asked
explicitly, and the CI baseline is computed from the reviewed subset only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

#: The three verdicts a case can be labeled with. These mirror the product's
#: per-attack statuses; `error` and `not_ai_judged` are deliberately excluded —
#: they describe a pipeline outcome, not a judgement anyone can be right about.
VERDICTS = ("vulnerable", "held", "needs_review")

#: A label is only ground truth once a person has confirmed it.
REVIEW_STATUSES = ("UNREVIEWED", "REVIEWED")

DEFAULT_BENCHMARK_PATH = Path(__file__).parent / "data" / "benchmark_v1.yaml"


class BenchmarkError(ValueError):
    """The benchmark file is malformed. Raised with the offending case id."""


@dataclass(frozen=True)
class BenchmarkCase:
    """One frozen, human-reviewable judgement."""

    id: str
    attack_id: str
    attack_name: str
    #: What the attack is attempting, in a sentence — so the reviewer need not
    #: look it up.
    attack_intent: str
    #: What a successful attack looks like for this case, in the reviewer's terms.
    success_criteria: str
    #: The actual text a target model produced. Verbatim, never truncated.
    response: str
    verdict: str
    #: Why that verdict, in a sentence a person can check against the response.
    rationale: str
    review_status: str
    #: "machine" until a person edits the label; then "human".
    proposed_by: str
    source: dict[str, Any] = field(default_factory=dict)
    #: Who confirmed or changed this label, when, and what they replaced.
    #: Empty until a person has decided. See ``review.py``.
    review: dict[str, Any] = field(default_factory=dict)

    @property
    def reviewed(self) -> bool:
        return self.review_status == "REVIEWED"


@dataclass(frozen=True)
class Benchmark:
    """A versioned set of cases."""

    version: str
    cases: tuple[BenchmarkCase, ...]
    path: Path | None = None

    def reviewed(self) -> tuple[BenchmarkCase, ...]:
        return tuple(case for case in self.cases if case.reviewed)

    def unreviewed(self) -> tuple[BenchmarkCase, ...]:
        return tuple(case for case in self.cases if not case.reviewed)

    def __len__(self) -> int:
        return len(self.cases)


def _require(raw: dict[str, Any], key: str, case_id: str) -> Any:
    if key not in raw or raw[key] in (None, ""):
        raise BenchmarkError(f"case {case_id!r}: missing required field {key!r}")
    return raw[key]


def parse_case(raw: dict[str, Any], index: int) -> BenchmarkCase:
    """Build one case, failing loudly on anything a reviewer would need."""
    case_id = str(raw.get("id") or f"<case #{index}>")

    verdict = str(_require(raw, "verdict", case_id))
    if verdict not in VERDICTS:
        raise BenchmarkError(
            f"case {case_id!r}: verdict {verdict!r} is not one of {VERDICTS}"
        )

    review_status = str(raw.get("review_status", "UNREVIEWED"))
    if review_status not in REVIEW_STATUSES:
        raise BenchmarkError(
            f"case {case_id!r}: review_status {review_status!r} is not one of "
            f"{REVIEW_STATUSES}"
        )

    # A rationale is mandatory even for an unreviewed case: a candidate label a
    # reviewer cannot evaluate is worse than no candidate at all.
    rationale = str(_require(raw, "rationale", case_id)).strip()
    if len(rationale) < 15:
        raise BenchmarkError(
            f"case {case_id!r}: rationale is too short to review ({rationale!r})"
        )

    return BenchmarkCase(
        id=case_id,
        attack_id=str(_require(raw, "attack_id", case_id)),
        attack_name=str(_require(raw, "attack_name", case_id)),
        attack_intent=str(_require(raw, "attack_intent", case_id)),
        success_criteria=str(_require(raw, "success_criteria", case_id)),
        response=str(_require(raw, "response", case_id)),
        verdict=verdict,
        rationale=rationale,
        review_status=review_status,
        proposed_by=str(raw.get("proposed_by", "machine")),
        source=dict(raw.get("source") or {}),
        review=dict(raw.get("review") or {}),
    )


def load_benchmark(path: Path | str | None = None) -> Benchmark:
    """Load and validate a benchmark file."""
    resolved = Path(path) if path is not None else DEFAULT_BENCHMARK_PATH
    if not resolved.exists():
        raise BenchmarkError(f"benchmark file not found: {resolved}")

    with open(resolved, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    version = str(data.get("version") or "")
    if not version:
        raise BenchmarkError(f"{resolved}: benchmark declares no version")

    raw_cases = data.get("cases") or []
    if not isinstance(raw_cases, list):
        raise BenchmarkError(f"{resolved}: 'cases' must be a list")

    cases = tuple(parse_case(raw, index) for index, raw in enumerate(raw_cases))

    seen: set[str] = set()
    for case in cases:
        if case.id in seen:
            raise BenchmarkError(f"duplicate case id {case.id!r}")
        seen.add(case.id)

    return Benchmark(version=version, cases=cases, path=resolved)


def dump_benchmark(benchmark: Benchmark, path: Path | str) -> Path:
    """Write a benchmark back out in the reviewable layout.

    Block scalars for the response and rationale so a reviewer reads real text
    in a diff rather than one long escaped line.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    def _case_payload(case: BenchmarkCase) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": case.id,
            "review_status": case.review_status,
            "proposed_by": case.proposed_by,
            "attack_id": case.attack_id,
            "attack_name": case.attack_name,
            "attack_intent": case.attack_intent,
            "success_criteria": case.success_criteria,
            "source": case.source,
            "response": case.response,
            "verdict": case.verdict,
            "rationale": case.rationale,
        }
        # Omitted entirely while empty, so an unreviewed case does not carry a
        # placeholder field through every diff.
        if case.review:
            payload["review"] = case.review
        return payload

    payload = {
        "version": benchmark.version,
        "cases": [_case_payload(case) for case in benchmark.cases],
    }

    # yaml.SafeDumper is untyped, so a plain subclass trips mypy --strict. Build
    # it dynamically and keep the untyped surface to this one binding.
    dumper_cls: Any = type("_BenchmarkDumper", (yaml.SafeDumper,), {})

    def _str_presenter(dumper: Any, value: str) -> Any:
        if "\n" in value or len(value) > 90:
            return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", value)

    dumper_cls.add_representer(str, _str_presenter)

    header = (
        "# PromptShield verdict benchmark\n"
        "#\n"
        "# Each case is self-contained: the attack, what it attempts, what counts as\n"
        "# success, the exact response a target model produced, and a proposed\n"
        "# verdict with a rationale. Everything needed to confirm or correct a label\n"
        "# is in the case — no need to run the scanner or open the attack library.\n"
        "#\n"
        "# review_status is UNREVIEWED until a person has checked the label. Machine\n"
        "# -proposed labels are candidates, not ground truth. Review them with\n"
        "#     promptshield eval review\n"
        "# which shows one case at a time and records who decided what. Editing\n"
        "# this file by hand works too: fix verdict/rationale, then set\n"
        "# review_status to REVIEWED (and proposed_by: human if you changed it).\n"
        "#\n"
        f"# Generated {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
    )
    # Written to a sibling temp file and moved into place. The review command
    # saves after every single decision, so a save is the most likely moment
    # to be interrupted, and a half-written benchmark would lose every label
    # in the file rather than just the one being recorded.
    tmp = out.with_name(out.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(header)
        yaml.dump(
            payload, handle, Dumper=dumper_cls, sort_keys=False, allow_unicode=True, width=88
        )
    os.replace(tmp, out)
    return out
