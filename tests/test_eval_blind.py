"""Blind labelling: capture with no proposal, label without seeing one, and
refuse to score anything left unlabelled.

holdout_v2 is labelled blind (docs/HOLDOUT_V2_PROTOCOL.md, Amendment 1): the
seed script records replies only, the review command shows no machine proposal,
and scoring refuses a file with a case nobody has labelled.
"""
from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from click.testing import CliRunner
from eval_helpers import StubJudge, write_benchmark

from promptshield.evaluation import cli as eval_cli
from promptshield.evaluation.benchmark import (
    NO_PROPOSAL,
    BenchmarkError,
    dump_benchmark,
    load_benchmark,
)
from promptshield.evaluation.review import (
    MIN_REASON_CHARS,
    ReviewError,
    blind_queue,
    confirm_case,
    label_case,
)
from promptshield.evaluation.runner import UnlabelledBenchmarkError, run_benchmark_sync

ATTACK = "PS-LLM01-001"
NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
REASON = "the reply recites the planted override code verbatim"
REPO = Path(__file__).resolve().parent.parent


def _write_raw(path: Path, cases: list[dict[str, Any]]) -> Path:
    full = []
    for index, case in enumerate(cases, start=1):
        entry: dict[str, Any] = {
            "id": case.get("id", f"H2-{index:04d}"),
            "review_status": case.get("review_status", "UNREVIEWED"),
            "proposed_by": case.get("proposed_by", NO_PROPOSAL),
            "attack_id": case.get("attack_id", ATTACK),
            "attack_name": "Test attack",
            "attack_intent": "Attempts something testable.",
            "success_criteria": "Succeeds if the response complies.",
            "source": {"prompt": "leaky", "target_model": "stub"},
            "response": case.get("response", "Sure, here you go."),
        }
        for key in ("verdict", "rationale"):
            if key in case:
                entry[key] = case[key]
        full.append(entry)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump({"version": "holdout-2.0.0", "cases": full}, handle, sort_keys=False)
    return path


class TestTheUnlabelledFormat:
    def test_a_case_with_no_proposal_loads_with_no_label(self, tmp_path: Path) -> None:
        case = load_benchmark(_write_raw(tmp_path / "b.yaml", [{}])).cases[0]
        assert not case.labelled
        assert case.verdict == "" and case.rationale == ""
        assert case.proposed_by == NO_PROPOSAL

    def test_it_round_trips_without_writing_a_placeholder_label(self, tmp_path: Path) -> None:
        path = _write_raw(tmp_path / "b.yaml", [{}])
        dump_benchmark(load_benchmark(path), path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))["cases"][0]
        assert "verdict" not in raw and "rationale" not in raw
        assert not load_benchmark(path).cases[0].labelled

    def test_a_no_proposal_case_carrying_a_verdict_is_refused(self, tmp_path: Path) -> None:
        path = _write_raw(tmp_path / "b.yaml", [{"verdict": "held"}])
        with pytest.raises(BenchmarkError, match="no verdict"):
            load_benchmark(path)

    def test_a_reviewed_case_cannot_claim_no_proposal(self, tmp_path: Path) -> None:
        path = _write_raw(tmp_path / "b.yaml", [{"review_status": "REVIEWED"}])
        with pytest.raises(BenchmarkError, match="UNREVIEWED"):
            load_benchmark(path)

    def test_a_machine_case_still_needs_its_verdict(self, tmp_path: Path) -> None:
        path = _write_raw(tmp_path / "b.yaml", [{"proposed_by": "machine"}])
        with pytest.raises(BenchmarkError, match="verdict"):
            load_benchmark(path)


class TestScoringRefusesUnlabelledCases:
    def test_the_runner_refuses_before_any_judge_call(self, tmp_path: Path) -> None:
        path = _write_raw(
            tmp_path / "b.yaml",
            [
                {"review_status": "REVIEWED", "proposed_by": "human", "verdict": "held",
                 "rationale": "the target refused and disclosed nothing"},
                {},
            ],
        )
        judge = StubJudge({})
        with pytest.raises(UnlabelledBenchmarkError, match="H2-0002"):
            run_benchmark_sync(load_benchmark(path), judge=judge)
        assert judge.calls == []

    def test_include_unreviewed_does_not_get_round_it(self, tmp_path: Path) -> None:
        path = _write_raw(tmp_path / "b.yaml", [{}])
        with pytest.raises(UnlabelledBenchmarkError):
            run_benchmark_sync(load_benchmark(path), judge=StubJudge({}), include_unreviewed=True)

    def test_a_failed_capture_is_excluded_and_counted(self, tmp_path: Path) -> None:
        path = _write_raw(
            tmp_path / "b.yaml",
            [
                {"review_status": "REVIEWED", "proposed_by": "human", "verdict": "held",
                 "rationale": "the target refused and disclosed nothing"},
                {"response": "[TIMEOUT] no reply within the limit"},
            ],
        )
        report = run_benchmark_sync(load_benchmark(path), judge=StubJudge({}))
        assert [result.case.id for result in report.results] == ["H2-0001"]
        assert report.provenance["cases_excluded_capture_failed"] == 1

    def test_eval_run_exits_nonzero_and_says_how_to_label(self, tmp_path: Path) -> None:
        path = _write_raw(tmp_path / "b.yaml", [{}])
        result = CliRunner().invoke(
            eval_cli.evaluate, ["run", "--judge", "none", "--benchmark", str(path)]
        )
        assert result.exit_code == 2
        assert "review --blind" in result.output

    def test_a_fully_labelled_benchmark_still_scores(self, tmp_path: Path) -> None:
        path = write_benchmark(tmp_path / "b.yaml", [{"attack_id": ATTACK, "verdict": "held"}])
        report = run_benchmark_sync(load_benchmark(path), judge=StubJudge({}))
        assert report.metrics.total == 1


class TestBlindLabelling:
    def test_the_queue_is_file_order_and_skips_failed_captures(self, tmp_path: Path) -> None:
        path = _write_raw(
            tmp_path / "b.yaml",
            [
                {"proposed_by": "machine", "verdict": "held",
                 "rationale": "CANDIDATE (unreviewed). judge said held"},
                {"response": "[ERROR] connection refused"},
                {"proposed_by": "machine", "verdict": "vulnerable",
                 "rationale": "CANDIDATE (unreviewed). judge said vulnerable"},
                {},
            ],
        )
        queue = blind_queue(load_benchmark(path))
        assert [case.id for case in queue] == ["H2-0001", "H2-0003", "H2-0004"]

    def test_a_label_is_the_labellers_own(self, tmp_path: Path) -> None:
        case = load_benchmark(_write_raw(tmp_path / "b.yaml", [{}])).cases[0]
        labelled = label_case(case, "vulnerable", REASON, "SalCyberAware", now=NOW)
        assert labelled.verdict == "vulnerable"
        assert labelled.rationale == REASON
        assert labelled.review_status == "REVIEWED"
        assert labelled.proposed_by == "human"
        assert labelled.review["action"] == "labelled_blind"

    def test_every_label_needs_a_rationale(self, tmp_path: Path) -> None:
        case = load_benchmark(_write_raw(tmp_path / "b.yaml", [{}])).cases[0]
        with pytest.raises(ReviewError, match=str(MIN_REASON_CHARS)):
            label_case(case, "held", "ok", "SalCyberAware")

    def test_a_hidden_candidate_is_kept_but_never_the_label(self, tmp_path: Path) -> None:
        case = load_benchmark(
            _write_raw(
                tmp_path / "b.yaml",
                [{"proposed_by": "machine", "verdict": "held",
                  "rationale": "CANDIDATE (unreviewed). judge said held"}],
            )
        ).cases[0]
        labelled = label_case(case, "held", REASON, "SalCyberAware", now=NOW)
        assert labelled.rationale == REASON
        assert labelled.proposed_by == "human"
        assert labelled.review["unseen_proposal"] == "held"

    def test_an_unlabelled_case_cannot_be_confirmed(self, tmp_path: Path) -> None:
        case = load_benchmark(_write_raw(tmp_path / "b.yaml", [{}])).cases[0]
        with pytest.raises(ReviewError, match="blind"):
            confirm_case(case, "SalCyberAware")


class TestTheBlindReviewCommand:
    SECRET_RATIONALE = "CANDIDATE (unreviewed). Judge said succeeded at confidence 0.93"

    def _path(self, tmp_path: Path) -> Path:
        return _write_raw(
            tmp_path / "b.yaml",
            [
                {"proposed_by": "machine", "verdict": "vulnerable",
                 "rationale": self.SECRET_RATIONALE},
                {},
            ],
        )

    def _review(self, path: Path, keys: str) -> Any:
        return CliRunner().invoke(
            eval_cli.evaluate,
            ["review", "--blind", "--benchmark", str(path), "--reviewer", "SalCyberAware"],
            input=keys,
        )

    def test_no_proposal_or_rationale_is_ever_shown(self, tmp_path: Path) -> None:
        result = self._review(self._path(tmp_path), "s\ns\n")
        assert result.exit_code == 0, result.output
        assert "CANDIDATE" not in result.output
        assert "0.93" not in result.output
        assert "proposed label" not in result.output
        assert "[c]onfirm" not in result.output

    def test_confirm_is_not_an_option(self, tmp_path: Path) -> None:
        path = self._path(tmp_path)
        result = self._review(path, "c\nq\n")
        assert result.exit_code == 0, result.output
        assert all(not case.reviewed for case in load_benchmark(path).cases)

    def test_a_label_without_a_reason_is_not_recorded(self, tmp_path: Path) -> None:
        path = self._path(tmp_path)
        # A too-short reason is refused and asked again; then input runs out.
        result = self._review(path, "h\nok\n")
        assert result.exit_code == 0, result.output
        assert all(not case.reviewed for case in load_benchmark(path).cases)

    def test_each_label_is_saved_with_its_rationale(self, tmp_path: Path) -> None:
        path = self._path(tmp_path)
        result = self._review(path, f"h\n{REASON}\nv\n{REASON}\n")
        assert result.exit_code == 0, result.output
        first, second = load_benchmark(path).cases
        assert (first.verdict, first.rationale, first.proposed_by) == ("held", REASON, "human")
        assert first.review["unseen_proposal"] == "vulnerable"
        assert (second.verdict, second.review_status) == ("vulnerable", "REVIEWED")

    def test_the_sighted_review_refuses_unlabelled_cases(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            eval_cli.evaluate,
            ["review", "--benchmark", str(_write_raw(tmp_path / "b.yaml", [{}]))],
            input="q\n",
        )
        assert result.exit_code != 0
        assert "--blind" in result.output


def _load_seed_script(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import scripts/seed_benchmark.py without letting it read any env file."""
    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", lambda *args, **kwargs: False)
    spec = importlib.util.spec_from_file_location(
        "seed_benchmark_under_test", REPO / "scripts" / "seed_benchmark.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


class _ScriptedScanner:
    """Stands in for the target: replies from a script, in order."""

    replies: list[str] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def send_attack(self, attack: Any) -> str:
        return _ScriptedScanner.replies.pop(0)

    async def cleanup(self) -> None:
        pass


class TestSeedingWithNoJudge:
    async def test_replies_only_and_zero_judge_calls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seed = _load_seed_script(monkeypatch)
        attacks = seed.AttackLibrary().all()[:3]

        def _no_judges(*args: Any, **kwargs: Any) -> list[Any]:
            raise AssertionError("--no-judge must not build a judge")

        monkeypatch.setattr(seed, "build_web_analyzers", _no_judges)
        monkeypatch.setattr(seed, "resolve_attacks", lambda _set: attacks)
        monkeypatch.setattr(seed, "SystemPromptScanner", _ScriptedScanner)
        # First attack answers; second errors then answers; third errors twice.
        _ScriptedScanner.replies = [
            "I can't share that.",
            "[ERROR] connection reset", "Here is the policy.",
            "[TIMEOUT] no reply", "[ERROR] connection reset",
        ]

        out = tmp_path / "holdout.yaml"
        code = await seed.seed(
            out, None, "stub-model", "http://127.0.0.1:11434/v1", False, False, "all",
            False, ("holdout_v2_airline",), "H2", "holdout-2.0.0", no_judge=True,
        )
        assert code == 0
        assert _ScriptedScanner.replies == []

        benchmark = load_benchmark(out)
        assert [case.id for case in benchmark.cases] == ["H2-0001", "H2-0002", "H2-0003"]
        assert all(case.proposed_by == NO_PROPOSAL for case in benchmark.cases)
        assert not any(case.labelled for case in benchmark.cases)
        assert all("judge" not in case.source for case in benchmark.cases)
        assert benchmark.cases[1].response == "Here is the policy."
        assert benchmark.cases[1].source["recaptured"] is True
        assert benchmark.cases[2].capture_failed
        assert [case.id for case in benchmark.excluded()] == ["H2-0003"]

        raw = out.read_text(encoding="utf-8")
        assert "verdict:" not in raw and "rationale:" not in raw
