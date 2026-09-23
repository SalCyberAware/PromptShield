"""Run a benchmark through the real analyzer pipeline and score the result.

The pipeline here is the product's, not a reimplementation: the always-on
``PatternAnalyzer`` floor, the chosen AI judge, and the product's own
``_combine_verdicts``. Only the target call is absent, because a benchmark case
carries a frozen response — which is the entire point. ``status_for_verdicts``
mirrors the status rule in ``backend/scan.py::_project_attack``; a test asserts
the two agree so they cannot drift apart silently.

Every run records provenance (issue #2) — judge model id, attack library
version, PromptShield version, benchmark version and a timestamp — because two
accuracy numbers are only comparable when you know what produced them.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .. import __version__, model_config
from ..analyzers.pattern import PatternAnalyzer
from ..attacks.library import AttackLibrary
from ..engines.base import _combine_verdicts
from ..models import AnalyzerVerdict, Attack, Confidence
from .benchmark import Benchmark, BenchmarkCase
from .metrics import RunMetrics, score
from .prompts import resolve_prompt

#: Judge name -> factory. Kept a registry so `--judge` can name one and so a
#: test can substitute a stub without patching import machinery.
JUDGES: dict[str, Callable[[], Any]] = {}


def _claude_judge() -> Any:
    from ..analyzers.claude_analyzer import ClaudeAnalyzer

    return ClaudeAnalyzer(model=model_config.WEB_ANTHROPIC_JUDGE_MODEL)


def _gemini_judge() -> Any:
    from ..analyzers.gemini_analyzer import GeminiAnalyzer

    return GeminiAnalyzer()


def _openai_judge() -> Any:
    from ..analyzers.openai_analyzer import OpenAIAnalyzer

    return OpenAIAnalyzer()


JUDGES.update(claude=_claude_judge, gemini=_gemini_judge, openai=_openai_judge)

#: Fallback order per primary judge, mirroring the product's Claude -> Gemini
#: chain. A judge that declines to answer is not evidence about the response, so
#: the harness asks the next one rather than recording "unjudged".
JUDGE_FALLBACKS: dict[str, tuple[str, ...]] = {"claude": ("gemini",)}


def _judge_chain(judge_name: str) -> list[Any]:
    """Build the primary judge plus its fallbacks, skipping any that cannot start."""
    chain: list[Any] = []
    for name in (judge_name, *JUDGE_FALLBACKS.get(judge_name, ())):
        factory = JUDGES.get(name)
        if factory is None:
            continue
        try:
            chain.append(factory())
        except (ValueError, ImportError):
            # No key or no SDK for this tier: skip it, exactly as the product does.
            continue
    return chain or [_NullJudge()]


def status_for_verdicts(verdicts: list[AnalyzerVerdict]) -> str:
    """Map combined analyzer verdicts to a product status.

    Mirrors ``backend/scan.py::_project_attack``: a judged attack that produced
    a finding is ``vulnerable`` unless the combination flagged it for review or
    landed at LOW confidence, in which case it is ``needs_review``; no finding
    means ``held``.
    """
    success, _score, confidence, needs_manual_review = _combine_verdicts(verdicts)
    if not success:
        return "held"
    if needs_manual_review or confidence == Confidence.LOW:
        return "needs_review"
    return "vulnerable"


@dataclass(frozen=True)
class CaseResult:
    case: BenchmarkCase
    predicted: str
    judge_reasoning: str | None
    judge_confidence: float | None
    judge_errored: bool

    @property
    def agrees(self) -> bool:
        return self.predicted == self.case.verdict


@dataclass(frozen=True)
class RunReport:
    judge: str
    judge_model: str | None
    metrics: RunMetrics
    results: tuple[CaseResult, ...]
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def disagreements(self) -> tuple[CaseResult, ...]:
        return tuple(result for result in self.results if not result.agrees)


class _NullJudge:
    """Stands in for a judge that could not be constructed.

    Used by ``--judge none`` to score the pattern floor alone. Returning the
    error sentinel keeps it on the same contract as a real analyzer outage.
    """

    name = "none"
    model = None

    async def analyze(self, attack: Attack, response: str) -> AnalyzerVerdict:
        return AnalyzerVerdict(
            analyzer_name=self.name,
            success=False,
            confidence_score=0.0,
            reasoning="no AI judge configured",
        )


async def _judge_case(
    judges: list[Any], attack: Attack, response: str, system_prompt: str | None = None
) -> tuple[AnalyzerVerdict | None, bool]:
    """Walk the judge chain until one answers. Returns its verdict and whether all failed.

    Mirrors the product's cascade in ``BaseScanner._run_ai_with_cascade``: a
    raised exception or the 0.0-confidence internal-error sentinel both mean
    "this judge produced nothing, try the next". The case that made this matter
    is a judge declining outright -- the API refusing to generate a verdict for a
    jailbreak payload quoted for classification -- which is not a property of the
    response and which a different provider may well answer.
    """
    last: AnalyzerVerdict | None = None
    for judge in judges:
        try:
            verdict = await judge.analyze(attack, response, system_prompt)
        except Exception:  # noqa: BLE001 - a judge outage must not abort the run
            continue
        if verdict.confidence_score > 0.0:
            return verdict, False
        last = verdict
    return last, True


async def run_benchmark(
    benchmark: Benchmark,
    judge_name: str = "claude",
    judge: Any | None = None,
    judges: list[Any] | None = None,
    include_unreviewed: bool = False,
    library: AttackLibrary | None = None,
) -> RunReport:
    """Score ``benchmark`` with one judge.

    ``judge`` lets a caller inject an analyzer directly — the seam CI uses to run
    with mocked judges and spend nothing. ``include_unreviewed`` must be set
    explicitly to score against candidate labels; by default only reviewed cases
    count, because an unreviewed label is not ground truth.
    """
    library = library or AttackLibrary()
    attacks = {attack.id: attack for attack in library.all()}

    # Three seams, narrowest first: an explicit chain (what the fallback tests
    # use), a single injected judge (what CI's mocked run uses), or the
    # registry's chain for --judge.
    if judges is not None:
        chain = list(judges)
    elif judge is not None:
        chain = [judge]
    else:
        chain = _judge_chain(judge_name)
    judge = chain[0]

    cases = benchmark.cases if include_unreviewed else benchmark.reviewed()
    pattern = PatternAnalyzer()

    results: list[CaseResult] = []
    answered: dict[str, int] = {}
    for case in cases:
        attack = attacks.get(case.attack_id)
        if attack is None:
            raise ValueError(
                f"case {case.id!r} references unknown attack {case.attack_id!r}; "
                "the benchmark and the attack library are out of sync"
            )

        verdicts = [pattern.analyze(attack, case.response)]
        judge_verdict, errored = await _judge_case(
            chain, attack, case.response, resolve_prompt(str(case.source.get("prompt") or ""))
        )
        if judge_verdict is not None and not errored:
            verdicts.append(judge_verdict)

        # A judge that produced nothing leaves the pattern floor alone, which the
        # product reports as not_ai_judged. Recorded as such rather than being
        # silently scored as "held".
        predicted = "not_ai_judged" if errored else status_for_verdicts(verdicts)

        name = (
            getattr(judge_verdict, "analyzer_name", None) if not errored else None
        ) or "none"
        answered[name] = answered.get(name, 0) + 1

        results.append(
            CaseResult(
                case=case,
                predicted=predicted,
                judge_reasoning=(judge_verdict.reasoning if judge_verdict else None),
                judge_confidence=(
                    judge_verdict.confidence_score if judge_verdict else None
                ),
                judge_errored=errored,
            )
        )

    metrics = score([(result.case.verdict, result.predicted) for result in results])

    return RunReport(
        judge=getattr(judge, "name", judge_name),
        judge_model=(
            getattr(judge, "model", None)
            if isinstance(getattr(judge, "model", None), str)
            else None
        ),
        metrics=metrics,
        results=tuple(results),
        provenance={
            "promptshield_version": __version__,
            "benchmark_version": benchmark.version,
            "attack_library_version": library.version,
            "judge": getattr(judge, "name", judge_name),
            "judge_model": (
                getattr(judge, "model", None)
                if isinstance(getattr(judge, "model", None), str)
                else None
            ),
            "cases_scored": len(results),
            # Which judges could have answered, in order, and which actually did
            # for each case. A number produced partly by a fallback judge is not
            # the same measurement as one produced entirely by the primary.
            "judge_chain": [getattr(j, "name", "unknown") for j in chain],
            "judges_answered": {
                name: count for name, count in sorted(answered.items())
            },
            "included_unreviewed": include_unreviewed,
            "recorded_at": datetime.now(UTC).isoformat(),
        },
    )


def run_benchmark_sync(*args: Any, **kwargs: Any) -> RunReport:
    """Blocking wrapper, for the CLI and for tests."""
    return asyncio.run(run_benchmark(*args, **kwargs))
