"""Tests for benchmark scoring.

Per-class metrics exist because accuracy alone hides the failure that matters:
a judge that never says "vulnerable" still scores well against a mostly-held
benchmark. These pin that down.
"""
from __future__ import annotations

import pytest

from promptshield.evaluation.metrics import score


class TestAccuracy:
    def test_all_correct(self) -> None:
        metrics = score([("held", "held"), ("vulnerable", "vulnerable")])
        assert metrics.accuracy == 1.0
        assert metrics.correct == 2

    def test_all_wrong(self) -> None:
        metrics = score([("held", "vulnerable"), ("vulnerable", "held")])
        assert metrics.accuracy == 0.0

    def test_empty_run_is_zero_not_an_error(self) -> None:
        metrics = score([])
        assert metrics.total == 0
        assert metrics.accuracy == 0.0


class TestPerClass:
    def test_precision_and_recall_are_distinguished(self) -> None:
        # Judge calls everything vulnerable: perfect recall on vulnerable,
        # poor precision, and it never finds a held case.
        pairs = [
            ("vulnerable", "vulnerable"),
            ("held", "vulnerable"),
            ("held", "vulnerable"),
        ]
        metrics = score(pairs)

        vulnerable = metrics.class_for("vulnerable")
        assert vulnerable is not None
        assert vulnerable.recall == 1.0
        assert vulnerable.precision == pytest.approx(1 / 3)

        held = metrics.class_for("held")
        assert held is not None
        assert held.recall == 0.0
        assert held.support == 2

    def test_a_judge_that_never_flags_is_exposed_by_recall(self) -> None:
        """The failure accuracy alone would hide."""
        pairs = [("held", "held")] * 9 + [("vulnerable", "held")]
        metrics = score(pairs)

        assert metrics.accuracy == 0.9  # looks fine
        vulnerable = metrics.class_for("vulnerable")
        assert vulnerable is not None
        assert vulnerable.recall == 0.0  # but it caught nothing

    def test_a_class_with_no_support_scores_zero_not_nan(self) -> None:
        metrics = score([("held", "held")])
        needs_review = metrics.class_for("needs_review")
        assert needs_review is not None
        assert needs_review.support == 0
        assert needs_review.precision == 0.0
        assert needs_review.recall == 0.0
        assert needs_review.f1 == 0.0

    def test_f1_balances_precision_and_recall(self) -> None:
        pairs = [
            ("vulnerable", "vulnerable"),
            ("vulnerable", "held"),
            ("held", "vulnerable"),
        ]
        metrics = score(pairs)
        vulnerable = metrics.class_for("vulnerable")
        assert vulnerable is not None
        assert vulnerable.precision == pytest.approx(0.5)
        assert vulnerable.recall == pytest.approx(0.5)
        assert vulnerable.f1 == pytest.approx(0.5)


class TestConfusion:
    def test_records_what_became_what(self) -> None:
        metrics = score([("held", "vulnerable"), ("held", "vulnerable"), ("held", "held")])
        assert metrics.confusion["held"] == {"vulnerable": 2, "held": 1}

    def test_out_of_taxonomy_predictions_are_counted_wrong_not_dropped(self) -> None:
        """A judge that failed to answer got the case wrong."""
        metrics = score([("held", "not_ai_judged"), ("held", "held")])
        assert metrics.total == 2
        assert metrics.correct == 1
        assert metrics.confusion["held"]["not_ai_judged"] == 1
