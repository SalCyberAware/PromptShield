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
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .. import __version__, model_config
from ..analyzers.pattern import PatternAnalyzer
from ..attacks.library import AttackLibrary
from ..engines.base import (
    SECOND_OPINION_JUDGES,
    _combine_verdicts,
    canary_settles,
    needs_second_opinion,
    resolve_second_opinion,
)
from ..models import AnalyzerVerdict, Attack
from .benchmark import Benchmark, BenchmarkCase
from .metrics import RunMetrics, score
from .prompts import resolve_prompt


class JudgeUnavailableError(RuntimeError):
    """The primary judge cannot be used at all: credit, quota or credentials.

    Raised instead of falling through to the fallback. A scoring run whose
    primary judge is unpayable cannot produce a comparable number however many
    cases the fallback covers, and asking it to try spends a second provider's
    quota to produce a figure nobody can use -- which is exactly what happened
    once: 41 cases covered by a fallback that then hit its own limit, and an
    accuracy of 0.717 that meant nothing.
    """


#: A provider failure that no amount of retrying or falling through will fix.
_UNRECOVERABLE = re.compile(
    r"credit balance|billing|insufficient[_ ]quota|exceeded your current quota|"
    r"authentication|invalid[_ ]?api[_ ]?key|unauthorized|permission denied",
    re.I,
)


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
#: -> OpenAI chain. A judge that declines to answer is not evidence about the
#: response, so the harness asks the next one rather than recording "unjudged".
#: OpenAI is skipped for any case whose target is OpenAI-family -- see
#: ``model_config.judge_excluded_for_target``.
JUDGE_FALLBACKS: dict[str, tuple[str, ...]] = {"claude": ("gemini", "openai")}


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


def status_for_verdicts(
    verdicts: list[AnalyzerVerdict], attack: Attack | None = None
) -> str:
    """Map combined analyzer verdicts to a product status.

    Mirrors ``backend/scan.py::_project_attack``: a judged attack that produced
    a finding is ``vulnerable`` unless the combination flagged it for review,
    in which case it is ``needs_review``; no finding means ``held``. The
    confidence band plays no part. ``attack`` is passed through for the
    per-attack override threshold, exactly as the product passes it.
    """
    success, _score, _confidence, needs_manual_review = _combine_verdicts(verdicts, attack)
    if not success:
        return "held"
    if needs_manual_review:
        return "needs_review"
    return "vulnerable"


@dataclass(frozen=True)
class CaseResult:
    case: BenchmarkCase
    predicted: str
    judge_reasoning: str | None
    judge_confidence: float | None
    judge_errored: bool
    #: What the judge actually said -- success, failed or uncertain -- so a
    #: disagreement is read from the judge's answer, never inferred back from
    #: the status the pipeline turned it into. ``None`` when no judge answered.
    judge_verdict: str | None = None
    #: Which judge answered: the primary, or a fallback it fell through to.
    judge_name: str | None = None
    #: The second opinion on a borderline verdict (``needs_second_opinion``):
    #: which judge gave it and what it said. ``None`` when none was asked for,
    #: or when no later judge in the chain answered.
    second_judge_name: str | None = None
    second_judge_verdict: str | None = None
    second_judge_confidence: float | None = None
    second_judge_reasoning: str | None = None

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


@dataclass(frozen=True)
class _Judged:
    """What the judge chain produced for one case."""

    #: What the answering judge said, or the primary's failure when none did.
    first: AnalyzerVerdict | None
    #: Every judge in the chain failed.
    errored: bool
    #: The second opinion on a borderline ``first``, if one was asked and given.
    second: AnalyzerVerdict | None = None
    #: The second judge that would have been asked, when ``canary_settles``
    #: kept the question from being put to it.
    skipped_canary: str | None = None

    @property
    def combined(self) -> AnalyzerVerdict | None:
        """The verdict that goes into the combination with the floor."""
        if self.first is None or self.errored:
            return None
        if self.second is None:
            return self.first
        return resolve_second_opinion(self.first, self.second)


async def _judge_case(
    judges: list[Any],
    attack: Attack,
    response: str,
    system_prompt: str | None = None,
    attempts: dict[str, int] | None = None,
    target_model: str | None = None,
) -> _Judged:
    """Walk the judge chain until one answers, then get a second opinion if it is borderline.

    Mirrors ``BaseScanner._judge_attack``. A success or failed below
    ``SECOND_OPINION_BELOW`` is put to the answering judge's designated second
    judge (``SECOND_OPINION_JUDGES``) and to no other, under the same
    same-family rule as a fallback. When that judge is not in the chain, is
    excluded, or does not answer, the first verdict stands alone. A success the
    floor's canary check already proves is not put to it (``canary_settles``).

    Mirrors the product's cascade in ``BaseScanner._run_ai_with_cascade``: a
    raised exception or the 0.0-confidence internal-error sentinel both mean
    "this judge produced nothing, try the next". The case that made this matter
    is a judge declining outright -- the API refusing to generate a verdict for a
    jailbreak payload quoted for classification -- which is not a property of the
    response and which a different provider may well answer.

    ``target_model`` is the model that produced the response. A fallback judge
    from the same family is skipped -- never asked, not counted as called --
    exactly as the product leaves it out of the cascade. The primary is never
    skipped: ``--judge openai`` is an explicit request to measure that judge.
    """
    attempts = attempts if attempts is not None else {}
    index, verdict = await _walk_chain(
        judges, 0, attack, response, system_prompt, attempts, target_model
    )
    if index is None:
        return _Judged(first=verdict, errored=True)
    assert verdict is not None
    if not needs_second_opinion(verdict):
        return _Judged(first=verdict, errored=False)
    designated = SECOND_OPINION_JUDGES.get(verdict.analyzer_name)
    for position, judge in enumerate(judges):
        name = getattr(judge, "name", None)
        if position == index or designated is None or name != designated:
            continue
        if model_config.judge_excluded_for_target(designated, target_model):
            break
        if canary_settles(verdict, attack, response, system_prompt):
            return _Judged(first=verdict, errored=False, skipped_canary=designated)
        second = await _ask_once(judge, attack, response, system_prompt, attempts)
        return _Judged(first=verdict, errored=False, second=second)
    return _Judged(first=verdict, errored=False)


def _second_opinion_counts(
    counts: dict[str, dict[str, int]], judge_name: str
) -> dict[str, int]:
    """The provenance counters for one second-opinion judge, created on first use."""
    return counts.setdefault(judge_name, {"agreed": 0, "disagreed": 0, "skipped_canary": 0})


async def _ask_once(
    judge: Any,
    attack: Attack,
    response: str,
    system_prompt: str | None,
    attempts: dict[str, int],
) -> AnalyzerVerdict | None:
    """One call to one judge for a second opinion: its verdict, or ``None``.

    Never raises ``JudgeUnavailableError``: a second judge that cannot be paid
    for leaves the first verdict standing, it does not stop the run.
    """
    name = getattr(judge, "name", "second_judge")
    attempts[name] = attempts.get(name, 0) + 1
    try:
        verdict: AnalyzerVerdict = await judge.analyze(attack, response, system_prompt)
    except Exception:  # noqa: BLE001 - an unavailable second judge is not an error
        return None
    return verdict if verdict.confidence_score > 0.0 else None


async def _walk_chain(
    judges: list[Any],
    start: int,
    attack: Attack,
    response: str,
    system_prompt: str | None,
    attempts: dict[str, int],
    target_model: str | None,
) -> tuple[int | None, AnalyzerVerdict | None]:
    """Ask ``judges[start:]`` in order. Returns the answering index and its verdict.

    When none answers the index is ``None`` and the verdict is the first failure.
    """
    first_failure: AnalyzerVerdict | None = None
    for index, judge in enumerate(judges):
        if index < start:
            continue
        name = getattr(judge, "name", f"judge{index}")
        if index > 0 and model_config.judge_excluded_for_target(name, target_model):
            continue
        attempts[name] = attempts.get(name, 0) + 1
        try:
            verdict = await judge.analyze(attack, response, system_prompt)
        except Exception:  # noqa: BLE001 - a judge outage must not abort the run
            continue
        if verdict.confidence_score > 0.0:
            return index, verdict
        if index == 0 and _UNRECOVERABLE.search(str(verdict.reasoning or "")):
            # Stop the whole run rather than quietly re-scoring the remainder
            # with a different judge, which would leave one number describing
            # two different measurements.
            raise JudgeUnavailableError(
                f"{name} cannot be used: {str(verdict.reasoning or '').strip()[:200]}"
            )
        # Keep the *first* failure, not the last. When the whole chain fails the
        # primary's reason is the one worth reporting: a fallback's quota error
        # is a consequence of the primary having failed, and recording it
        # instead hides why anything fell through at all.
        if first_failure is None:
            first_failure = verdict
    return None, first_failure


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
    #: How often each judge was *asked*, which is the only way to see a fallback
    #: being reached at all. A fallback that is never called and a fallback that
    #: is called and fails look identical in `judges_answered` alone.
    attempts: dict[str, int] = {}
    #: Second-opinion judge -> how often it agreed and disagreed with the first.
    second_opinions: dict[str, dict[str, int]] = {}
    for case in cases:
        attack = attacks.get(case.attack_id)
        if attack is None:
            raise ValueError(
                f"case {case.id!r} references unknown attack {case.attack_id!r}; "
                "the benchmark and the attack library are out of sync"
            )

        # Floor and judge see the same system prompt, as they do in the product.
        system_prompt = resolve_prompt(str(case.source.get("prompt") or ""))
        verdicts = [pattern.analyze(attack, case.response, system_prompt)]
        judged = await _judge_case(
            chain,
            attack,
            case.response,
            system_prompt,
            attempts,
            target_model=str(case.source.get("target_model") or "") or None,
        )
        judge_verdict, errored, second = judged.first, judged.errored, judged.second
        if judged.combined is not None:
            verdicts.append(judged.combined)
        if second is not None and judge_verdict is not None:
            asked = _second_opinion_counts(second_opinions, second.analyzer_name)
            asked["agreed" if second.verdict == judge_verdict.verdict else "disagreed"] += 1
        if judged.skipped_canary is not None:
            _second_opinion_counts(second_opinions, judged.skipped_canary)["skipped_canary"] += 1

        # A judge that produced nothing leaves the pattern floor alone, which the
        # product reports as not_ai_judged. Recorded as such rather than being
        # silently scored as "held".
        predicted = "not_ai_judged" if errored else status_for_verdicts(verdicts, attack)

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
                judge_verdict=(
                    judge_verdict.verdict.value
                    if judge_verdict is not None and not errored and judge_verdict.verdict
                    else None
                ),
                judge_name=None if errored else name,
                second_judge_name=second.analyzer_name if second else None,
                second_judge_verdict=(
                    second.verdict.value if second is not None and second.verdict else None
                ),
                second_judge_confidence=second.confidence_score if second else None,
                second_judge_reasoning=second.reasoning if second else None,
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
            "judges_called": {name: count for name, count in sorted(attempts.items())},
            # Borderline verdicts put to a second judge. A number whose
            # needs_review count comes partly from judges disagreeing is not the
            # same measurement as one from a single judge.
            "second_opinions": {
                name: dict(counts) for name, counts in sorted(second_opinions.items())
            },
            "included_unreviewed": include_unreviewed,
            "recorded_at": datetime.now(UTC).isoformat(),
        },
    )


def run_benchmark_sync(*args: Any, **kwargs: Any) -> RunReport:
    """Blocking wrapper, for the CLI and for tests."""
    return asyncio.run(run_benchmark(*args, **kwargs))
