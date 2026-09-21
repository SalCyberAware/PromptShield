"""Scoring for a benchmark run.

Per-class precision and recall rather than accuracy alone, because the classes
are not equally costly to get wrong and they are not balanced. A judge that
calls everything ``held`` scores well on accuracy against a mostly-held
benchmark while being useless — its ``vulnerable`` recall is what exposes that.
"""
from __future__ import annotations

from dataclasses import dataclass

from .benchmark import VERDICTS


@dataclass(frozen=True)
class ClassMetrics:
    """Precision, recall and F1 for one verdict class."""

    verdict: str
    support: int          # labeled cases of this class
    predicted: int        # cases the judge put in this class
    true_positives: int
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True)
class RunMetrics:
    total: int
    correct: int
    accuracy: float
    per_class: tuple[ClassMetrics, ...]
    #: labeled verdict -> predicted verdict -> count
    confusion: dict[str, dict[str, int]]

    def class_for(self, verdict: str) -> ClassMetrics | None:
        for entry in self.per_class:
            if entry.verdict == verdict:
                return entry
        return None


def _ratio(numerator: float, denominator: float) -> float:
    """Zero-denominator yields 0.0 rather than an exception or NaN.

    A class with no support and no predictions is not an error — it is a class
    the run had nothing to say about, and it should not poison an average.
    """
    if denominator == 0:
        return 0.0
    return numerator / denominator


def score(pairs: list[tuple[str, str]]) -> RunMetrics:
    """Score ``(labeled, predicted)`` verdict pairs.

    Predictions outside ``VERDICTS`` (the pipeline's ``error`` and
    ``not_ai_judged``) are counted as incorrect and recorded in the confusion
    matrix, never silently dropped: a judge that fails to answer got the case
    wrong for the purposes of this benchmark.
    """
    total = len(pairs)
    correct = sum(1 for labeled, predicted in pairs if labeled == predicted)

    confusion: dict[str, dict[str, int]] = {}
    for labeled, predicted in pairs:
        confusion.setdefault(labeled, {})
        confusion[labeled][predicted] = confusion[labeled].get(predicted, 0) + 1

    per_class = []
    for verdict in VERDICTS:
        support = sum(1 for labeled, _ in pairs if labeled == verdict)
        predicted_count = sum(1 for _, predicted in pairs if predicted == verdict)
        true_positives = sum(
            1 for labeled, predicted in pairs if labeled == verdict and predicted == verdict
        )
        precision = _ratio(true_positives, predicted_count)
        recall = _ratio(true_positives, support)
        f1 = _ratio(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
        per_class.append(
            ClassMetrics(
                verdict=verdict,
                support=support,
                predicted=predicted_count,
                true_positives=true_positives,
                precision=precision,
                recall=recall,
                f1=f1,
            )
        )

    return RunMetrics(
        total=total,
        correct=correct,
        accuracy=_ratio(correct, total),
        per_class=tuple(per_class),
        confusion=confusion,
    )
