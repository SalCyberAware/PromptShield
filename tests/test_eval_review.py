"""Tests for the review workflow: queue order, decisions, and durability.

The decision logic is deliberately separate from the click command so it can be
tested without a terminal. What the command adds on top is display and prompting.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from eval_helpers import write_benchmark

from promptshield.evaluation.benchmark import dump_benchmark, load_benchmark
from promptshield.evaluation.prompts import (
    EXAMPLE_PROMPTS,
    HOLDOUT_PROMPT,
    HOLDOUT_PROMPTS,
    resolve_prompt,
)
from promptshield.evaluation.review import (
    MIN_REASON_CHARS,
    ReviewError,
    apply_decision,
    change_case,
    confirm_case,
    queue_summary,
    review_queue,
)

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
REASON = "the target refused outright and disclosed nothing"


def _benchmark(tmp_path: Path, cases: list[dict[str, object]]) -> object:
    return load_benchmark(write_benchmark(tmp_path / "b.yaml", cases))


class TestQueueOrder:
    def test_vulnerable_comes_first(self, tmp_path: Path) -> None:
        """The smallest class, and the one recall is computed from."""
        benchmark = _benchmark(
            tmp_path,
            [
                {"id": "BM-0001", "attack_id": "PS-LLM01-001", "verdict": "held",
                 "review_status": "UNREVIEWED"},
                {"id": "BM-0002", "attack_id": "PS-LLM01-001", "verdict": "vulnerable",
                 "review_status": "UNREVIEWED"},
                {"id": "BM-0003", "attack_id": "PS-LLM01-001", "verdict": "needs_review",
                 "review_status": "UNREVIEWED"},
            ],
        )
        assert [c.id for c in review_queue(benchmark)] == ["BM-0002", "BM-0003", "BM-0001"]

    def test_reviewed_cases_are_not_queued_again(self, tmp_path: Path) -> None:
        benchmark = _benchmark(
            tmp_path,
            [
                {"id": "BM-0001", "attack_id": "PS-LLM01-001", "verdict": "vulnerable",
                 "review_status": "REVIEWED"},
                {"id": "BM-0002", "attack_id": "PS-LLM01-001", "verdict": "vulnerable",
                 "review_status": "UNREVIEWED"},
            ],
        )
        assert [c.id for c in review_queue(benchmark)] == ["BM-0002"]

    def test_summary_counts_only_what_is_left(self, tmp_path: Path) -> None:
        benchmark = _benchmark(
            tmp_path,
            [
                {"id": "BM-0001", "attack_id": "PS-LLM01-001", "verdict": "held",
                 "review_status": "REVIEWED"},
                {"id": "BM-0002", "attack_id": "PS-LLM01-001", "verdict": "held",
                 "review_status": "UNREVIEWED"},
            ],
        )
        assert queue_summary(benchmark) == {"vulnerable": 0, "needs_review": 0, "held": 1}


class TestConfirm:
    def test_confirm_marks_reviewed_without_rewriting_the_label(self, tmp_path: Path) -> None:
        case = review_queue(
            _benchmark(tmp_path, [{"id": "BM-0001", "attack_id": "PS-LLM01-001",
                                   "verdict": "vulnerable", "review_status": "UNREVIEWED",
                                   "rationale": "Judge said the prompt was disclosed."}])
        )[0]
        done = confirm_case(case, "Reviewer", NOW)

        assert done.review_status == "REVIEWED"
        assert done.verdict == "vulnerable"
        assert done.rationale == case.rationale
        assert done.review["action"] == "confirmed"
        assert done.review["reviewer"] == "Reviewer"
        assert done.review["reviewed_at"] == NOW.isoformat()

    def test_confirming_leaves_proposed_by_as_machine(self, tmp_path: Path) -> None:
        """A confirmed machine proposal is not a human-authored label.

        Keeping them apart is what lets anyone ask later how good the candidate
        labels actually were.
        """
        case = review_queue(
            _benchmark(tmp_path, [{"id": "BM-0001", "attack_id": "PS-LLM01-001",
                                   "verdict": "held", "review_status": "UNREVIEWED",
                                   "proposed_by": "machine"}])
        )[0]
        assert confirm_case(case, "Reviewer", NOW).proposed_by == "machine"


class TestChange:
    @pytest.fixture
    def case(self, tmp_path: Path) -> object:
        return review_queue(
            _benchmark(tmp_path, [{"id": "BM-0001", "attack_id": "PS-LLM01-001",
                                   "verdict": "vulnerable", "review_status": "UNREVIEWED",
                                   "rationale": "CANDIDATE (unreviewed). Judge said succeeded."}])
        )[0]

    def test_change_records_the_new_label_and_the_reason(self, case: object) -> None:
        done = change_case(case, "held", REASON, "Reviewer", NOW)
        assert done.verdict == "held"
        assert done.rationale == REASON
        assert done.review_status == "REVIEWED"
        assert done.proposed_by == "human"
        assert done.review["action"] == "changed"
        assert done.review["previous_verdict"] == "vulnerable"

    def test_the_superseded_rationale_is_kept_not_deleted(self, case: object) -> None:
        done = change_case(case, "held", REASON, "Reviewer", NOW)
        assert done.review["superseded_rationale"] == case.rationale

    def test_a_reason_too_short_to_read_later_is_refused(self, case: object) -> None:
        with pytest.raises(ReviewError, match=str(MIN_REASON_CHARS)):
            change_case(case, "held", "wrong", "Reviewer", NOW)

    def test_changing_to_the_label_it_already_has_is_refused(self, case: object) -> None:
        with pytest.raises(ReviewError, match="already labeled"):
            change_case(case, "vulnerable", REASON, "Reviewer", NOW)

    def test_an_unknown_verdict_is_refused(self, case: object) -> None:
        with pytest.raises(ReviewError, match="not one of"):
            change_case(case, "maybe", REASON, "Reviewer", NOW)

    def test_the_new_rationale_survives_a_round_trip(self, case: object, tmp_path: Path) -> None:
        """A changed label must still satisfy the loader's own rationale rule."""
        benchmark = _benchmark(tmp_path, [{"id": "BM-0001", "attack_id": "PS-LLM01-001",
                                           "verdict": "vulnerable", "review_status": "UNREVIEWED"}])
        updated = apply_decision(benchmark, change_case(case, "held", REASON, "Reviewer", NOW))
        path = dump_benchmark(updated, tmp_path / "out.yaml")
        reloaded = load_benchmark(path)

        assert reloaded.cases[0].verdict == "held"
        assert reloaded.cases[0].rationale == REASON
        assert reloaded.cases[0].review["reviewer"] == "Reviewer"


class TestApplyDecision:
    def test_other_cases_and_file_order_are_untouched(self, tmp_path: Path) -> None:
        benchmark = _benchmark(
            tmp_path,
            [
                {"id": "BM-0001", "attack_id": "PS-LLM01-001", "verdict": "held",
                 "review_status": "UNREVIEWED"},
                {"id": "BM-0002", "attack_id": "PS-LLM01-001", "verdict": "vulnerable",
                 "review_status": "UNREVIEWED"},
                {"id": "BM-0003", "attack_id": "PS-LLM01-001", "verdict": "held",
                 "review_status": "UNREVIEWED"},
            ],
        )
        target = next(c for c in benchmark.cases if c.id == "BM-0002")
        updated = apply_decision(benchmark, confirm_case(target, "Reviewer", NOW))

        assert [c.id for c in updated.cases] == ["BM-0001", "BM-0002", "BM-0003"]
        assert [c.review_status for c in updated.cases] == [
            "UNREVIEWED", "REVIEWED", "UNREVIEWED",
        ]

    def test_a_case_from_another_benchmark_is_refused(self, tmp_path: Path) -> None:
        benchmark = _benchmark(tmp_path, [{"id": "BM-0001", "attack_id": "PS-LLM01-001",
                                           "verdict": "held", "review_status": "UNREVIEWED"}])
        stranger = benchmark.cases[0]
        other = _benchmark(tmp_path / "other", [{"id": "BM-0099", "attack_id": "PS-LLM01-001",
                                                 "verdict": "held", "review_status": "UNREVIEWED"}])
        with pytest.raises(ReviewError, match="not in this benchmark"):
            apply_decision(other, confirm_case(stranger, "Reviewer", NOW))


class TestDurability:
    def test_an_unreviewed_case_carries_no_empty_review_field(self, tmp_path: Path) -> None:
        """Keeps the diff of a review session to the cases actually decided."""
        benchmark = _benchmark(tmp_path, [{"id": "BM-0001", "attack_id": "PS-LLM01-001",
                                           "verdict": "held", "review_status": "UNREVIEWED"}])
        path = dump_benchmark(benchmark, tmp_path / "out.yaml")
        assert "review:" not in path.read_text(encoding="utf-8")

    def test_the_write_is_atomic_and_leaves_no_temp_file(self, tmp_path: Path) -> None:
        """The command saves after every decision, so a save is the risky moment."""
        benchmark = _benchmark(tmp_path, [{"id": "BM-0001", "attack_id": "PS-LLM01-001",
                                           "verdict": "held", "review_status": "UNREVIEWED"}])
        out = tmp_path / "out.yaml"
        dump_benchmark(benchmark, out)
        dump_benchmark(benchmark, out)
        assert list(out.parent.glob("*.tmp")) == []
        assert load_benchmark(out).version


class TestPrompts:
    def test_a_case_resolves_back_to_the_prompt_it_was_captured_against(self) -> None:
        """A reviewer cannot judge a leak without seeing what was leaked."""
        assert "SAVE40" in (resolve_prompt("leaky") or "")
        assert "Northwind Bank" in (resolve_prompt("hardened") or "")

    def test_an_unknown_prompt_key_resolves_to_nothing_rather_than_the_wrong_text(self) -> None:
        assert resolve_prompt("something-else") is None
        assert resolve_prompt(None) is None

    def test_the_seed_script_holds_no_second_copy_of_the_prompts(self) -> None:
        """Two copies would mean the reviewer could be shown text the target
        never received.

        Checked by reading the script rather than importing it: ``scripts`` is
        not a declared package, so it is not importable from an installed
        checkout, and a test that silently skipped there would protect nothing.
        """
        source = (
            Path(__file__).resolve().parent.parent / "scripts" / "seed_benchmark.py"
        ).read_text(encoding="utf-8")

        assert "EXAMPLE_PROMPTS" in source, "the seeder should import the shared prompts"
        for literal in ("SupportBot for QuickCart", "Aria, the customer support assistant"):
            assert literal not in source, (
                f"{literal!r} is defined in both the seeder and prompts.py"
            )
        for literal in ("SupportBot for QuickCart", "Aria, the customer support assistant"):
            assert any(literal in text for text in EXAMPLE_PROMPTS.values())


REPO = Path(__file__).resolve().parent.parent
HOLDOUT_PATH = REPO / "promptshield" / "evaluation" / "data" / "holdout_v1.yaml"


class TestTheHoldoutPrompt:
    def test_it_resolves_so_its_cases_can_be_reviewed_and_scored(self) -> None:
        assert resolve_prompt("holdout") == HOLDOUT_PROMPT

    def test_it_is_not_an_example_so_a_routine_seed_cannot_pick_it_up(self) -> None:
        assert "holdout" not in EXAMPLE_PROMPTS
        assert HOLDOUT_PROMPT not in EXAMPLE_PROMPTS.values()

    def test_it_stays_out_of_the_web_demo(self) -> None:
        demo = (REPO / "frontend" / "src" / "lib" / "examplePrompt.js").read_text(encoding="utf-8")
        assert "Brightwell" not in demo
        assert "6093218" not in demo

    def test_it_shares_no_business_or_secret_with_the_examples(self) -> None:
        for marker in ("QuickCart", "Northwind", "SAVE40", "4417", "SupportBot", "Aria"):
            assert marker not in HOLDOUT_PROMPT
        for marker in ("Brightwell", "violet harbor seventeen", "6093218"):
            assert all(marker not in text for text in EXAMPLE_PROMPTS.values())


class TestTheCommittedHoldout:
    def test_it_is_a_separate_versioned_set_captured_against_the_holdout_prompt(self) -> None:
        holdout = load_benchmark(HOLDOUT_PATH)
        main = load_benchmark()
        assert holdout.version != main.version
        assert len(holdout) == 50
        assert all(case.id.startswith("HO-") for case in holdout.cases)
        assert {case.source["prompt"] for case in holdout.cases} == set(HOLDOUT_PROMPTS)
        assert not {c.id for c in holdout.cases} & {c.id for c in main.cases}

    def test_every_case_carries_full_provenance(self) -> None:
        for case in load_benchmark(HOLDOUT_PATH).cases:
            for key in ("target_model", "target_base_url", "judge", "judge_model", "captured_at"):
                assert case.source.get(key), f"{case.id} lacks {key}"
