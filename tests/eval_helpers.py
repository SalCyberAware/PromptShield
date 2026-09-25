"""Shared fixtures for the eval-harness tests.

Every judge here is a stub. Nothing in the test suite may reach a provider: the
CI job that runs these is given no API keys precisely so that a code path which
started calling one would fail loudly rather than bill silently.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from promptshield.models import AnalyzerVerdict, JudgeVerdict


class StubJudge:
    """A judge whose verdict per attack id is decided by the test.

    Each verdict is ``(outcome, confidence)``, where outcome is a bool (the
    legacy success/failed form) or a three-way label such as ``"uncertain"``.
    """

    def __init__(self, verdicts: dict[str, tuple[bool | str, float]], name: str = "stub_judge",
                 model: str | None = "stub-model-v1") -> None:
        self._verdicts = verdicts
        self.name = name
        self.model = model
        self.calls: list[str] = []
        #: What the judge was told the target's system prompt was, per call.
        self.system_prompts: list[str | None] = []

    async def analyze(
        self, attack: Any, response: str, system_prompt: str | None = None
    ) -> AnalyzerVerdict:
        self.calls.append(attack.id)
        self.system_prompts.append(system_prompt)
        outcome, confidence = self._verdicts.get(attack.id, (False, 0.9))
        if isinstance(outcome, str):
            verdict = JudgeVerdict(outcome)
        else:
            verdict = JudgeVerdict.SUCCESS if outcome else JudgeVerdict.FAILED
        return AnalyzerVerdict(
            analyzer_name=self.name,
            success=verdict == JudgeVerdict.SUCCESS,
            verdict=verdict,
            confidence_score=confidence,
            reasoning=f"stub verdict for {attack.id}",
        )


class ExplodingJudge:
    """A judge that always raises — the provider-outage path."""

    name = "exploding_judge"
    model = "stub-model-v1"

    async def analyze(
        self, attack: Any, response: str, system_prompt: str | None = None
    ) -> AnalyzerVerdict:
        raise RuntimeError("judge is down")


def write_benchmark(path: Path, cases: list[dict[str, Any]], version: str = "1.0.0") -> Path:
    """Write a benchmark file from case dicts, filling in the boilerplate."""
    full = []
    for index, case in enumerate(cases, start=1):
        full.append(
            {
                "id": case.get("id", f"BM-{index:04d}"),
                "review_status": case.get("review_status", "REVIEWED"),
                "proposed_by": case.get("proposed_by", "human"),
                "attack_id": case["attack_id"],
                "attack_name": case.get("attack_name", "Test attack"),
                "attack_intent": case.get("attack_intent", "Attempts something testable."),
                "success_criteria": case.get(
                    "success_criteria", "Succeeds if the response complies."
                ),
                "source": case.get("source", {"prompt": "leaky"}),
                "response": case.get("response", "Sure, here you go."),
                "verdict": case["verdict"],
                "rationale": case.get(
                    "rationale", "The response plainly complies with the request."
                ),
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump({"version": version, "cases": full}, handle, sort_keys=False)
    return path
