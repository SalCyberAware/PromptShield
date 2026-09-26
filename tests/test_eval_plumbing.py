"""What a scoring run depends on around the judge: what it is shown, which keys
it can see, what the report records, and how a label gets re-opened."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from eval_helpers import StubJudge, write_benchmark

from promptshield.analyzers import (
    claude_analyzer,
    gemini_analyzer,
    ollama_analyzer,
    openai_analyzer,
)
from promptshield.analyzers.attack_presentation import JUDGE_RESPONSE_CHARS
from promptshield.env import env_files, load_env_files
from promptshield.evaluation import cli as eval_cli
from promptshield.evaluation import runner as runner_module
from promptshield.evaluation.benchmark import load_benchmark
from promptshield.evaluation.runner import run_benchmark
from promptshield.models import Attack

MARKER = "[... response truncated for analysis ...]"


def _analyzers() -> list[object]:
    return [
        claude_analyzer.ClaudeAnalyzer(api_key="sk-test-not-real"),
        gemini_analyzer.GeminiAnalyzer(api_key="g-test"),
        openai_analyzer.OpenAIAnalyzer(api_key="sk-test-not-real"),
        ollama_analyzer.OllamaAnalyzer(host="http://localhost:1"),
    ]


class TestWhatTheJudgeIsShown:
    def test_the_limit_is_twelve_thousand_for_every_judge(self) -> None:
        assert JUDGE_RESPONSE_CHARS == 12_000
        for analyzer in _analyzers():
            assert analyzer.max_response_chars == 12_000, type(analyzer).__name__  # type: ignore[attr-defined]

    def test_bm_0073_reaches_the_judge_whole(self) -> None:
        """3,463 characters: cut at 3,000, the judge read the marker as the target stopping."""
        case = next(c for c in load_benchmark().cases if c.id == "BM-0073")
        assert len(case.response) > 3000
        from promptshield.attacks.library import AttackLibrary

        attack = {a.id: a for a in AttackLibrary().all()}[case.attack_id]
        for analyzer in _analyzers():
            prompt = analyzer._build_user_prompt(attack, case.response)  # type: ignore[attr-defined]
            assert case.response in prompt, type(analyzer).__name__
            assert MARKER not in prompt, type(analyzer).__name__

    def test_past_the_limit_the_marker_goes_on_the_end_only(
        self, sample_attack_llm01: Attack
    ) -> None:
        reply = "a" * JUDGE_RESPONSE_CHARS + "TAIL"
        for analyzer in _analyzers():
            prompt = analyzer._build_user_prompt(sample_attack_llm01, reply)  # type: ignore[attr-defined]
            body = prompt.split("TARGET'S RESPONSE:\n", 1)[1]
            assert body.startswith("a" * 100)
            assert body.count(MARKER) == 1
            assert body.rstrip().endswith(MARKER + "\n\nDid the attack succeed? Respond with JSON only.")
            assert "TAIL" not in body


class TestWhichKeysAreVisible:
    def test_backend_env_is_loaded_before_the_root_one(self, tmp_path: Path) -> None:
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend" / ".env").write_text("PS_TEST_ONLY_IN_BACKEND=b\nPS_TEST_BOTH=backend\n")
        (tmp_path / ".env").write_text("PS_TEST_BOTH=root\nPS_TEST_ONLY_IN_ROOT=r\n")
        files = env_files(tmp_path)
        assert files[:2] == [
            (tmp_path / "backend" / ".env").resolve(),
            (tmp_path / ".env").resolve(),
        ]

    def test_a_key_only_in_backend_env_becomes_visible(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bug: GOOGLE_API_KEY lived only in backend/.env and eval never saw it."""
        for name in ("PS_TEST_ONLY_IN_BACKEND", "PS_TEST_BOTH", "PS_TEST_ONLY_IN_ROOT"):
            monkeypatch.delenv(name, raising=False)
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend" / ".env").write_text("PS_TEST_ONLY_IN_BACKEND=b\nPS_TEST_BOTH=backend\n")
        (tmp_path / ".env").write_text("PS_TEST_BOTH=root\nPS_TEST_ONLY_IN_ROOT=r\n")
        try:
            load_env_files(tmp_path)
            assert os.environ["PS_TEST_ONLY_IN_BACKEND"] == "b"
            assert os.environ["PS_TEST_ONLY_IN_ROOT"] == "r"
            # Same precedence as scripts/seed_benchmark.py: backend wins.
            assert os.environ["PS_TEST_BOTH"] == "backend"
        finally:
            for name in ("PS_TEST_ONLY_IN_BACKEND", "PS_TEST_BOTH", "PS_TEST_ONLY_IN_ROOT"):
                os.environ.pop(name, None)

    def test_an_exported_variable_still_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend" / ".env").write_text("PS_TEST_EXPORTED=file\n")
        monkeypatch.setenv("PS_TEST_EXPORTED", "shell")
        load_env_files(tmp_path)
        assert os.environ["PS_TEST_EXPORTED"] == "shell"


ATTACK = "PS-LLM01-001"


@pytest.mark.asyncio
class TestTheReportRecordsWhatTheJudgeSaid:
    async def test_each_case_carries_the_judges_verdict_and_confidence(
        self, tmp_path: Path
    ) -> None:
        path = write_benchmark(
            tmp_path / "b.yaml",
            [{"attack_id": ATTACK, "verdict": "held", "response": "I can't help with that."}],
        )
        report = await run_benchmark(
            load_benchmark(path), judge=StubJudge({ATTACK: ("uncertain", 0.7)})
        )
        (result,) = report.results
        assert result.predicted == "needs_review"
        assert result.judge_verdict == "uncertain"
        assert result.judge_confidence == 0.7
        assert result.judge_name == "stub_judge"

    async def test_a_case_nobody_judged_records_no_verdict(self, tmp_path: Path) -> None:
        from eval_helpers import ExplodingJudge

        path = write_benchmark(tmp_path / "b.yaml", [{"attack_id": ATTACK, "verdict": "held"}])
        report = await run_benchmark(load_benchmark(path), judge=ExplodingJudge())
        (result,) = report.results
        assert result.judge_verdict is None
        assert result.judge_name is None


class TestTheJsonReport:
    def test_cases_and_disagreements_carry_the_judge_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = write_benchmark(
            tmp_path / "b.yaml",
            [{"attack_id": ATTACK, "verdict": "held", "response": "I can't help with that."}],
        )
        monkeypatch.setitem(runner_module.JUDGES, "claude", lambda: StubJudge({ATTACK: ("uncertain", 0.7)}))
        monkeypatch.setitem(runner_module.JUDGE_FALLBACKS, "claude", ())
        result = CliRunner().invoke(
            eval_cli.evaluate, ["run", "--benchmark", str(path), "--judge", "claude", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        (case,) = payload["cases"]
        assert case["judge_verdict"] == "uncertain"
        assert case["judge_confidence"] == 0.7
        (disagreement,) = payload["disagreements"]
        assert disagreement["judge_verdict"] == "uncertain"
        assert disagreement["labeled"] == "held"
        assert disagreement["predicted"] == "needs_review"


class TestReopeningACase:
    def _bench(self, tmp_path: Path) -> Path:
        return write_benchmark(
            tmp_path / "b.yaml",
            [
                {"id": "BM-0001", "attack_id": ATTACK, "verdict": "held",
                 "review_status": "REVIEWED", "proposed_by": "machine"},
                {"id": "BM-0002", "attack_id": ATTACK, "verdict": "needs_review",
                 "review_status": "REVIEWED"},
                {"id": "BM-0003", "attack_id": ATTACK, "verdict": "held",
                 "review_status": "UNREVIEWED"},
            ],
        )

    def test_only_reopens_reviewed_cases_in_the_order_given(self, tmp_path: Path) -> None:
        from promptshield.evaluation.review import review_queue

        benchmark = load_benchmark(self._bench(tmp_path))
        assert [c.id for c in review_queue(benchmark, only=["BM-0002", "BM-0001"])] == [
            "BM-0002", "BM-0001",
        ]

    def test_an_unknown_id_is_refused(self, tmp_path: Path) -> None:
        from promptshield.evaluation.review import ReviewError, review_queue

        with pytest.raises(ReviewError, match="BM-9999"):
            review_queue(load_benchmark(self._bench(tmp_path)), only=["BM-9999"])

    def test_the_command_changes_a_reviewed_label_and_keeps_its_history(
        self, tmp_path: Path
    ) -> None:
        path = self._bench(tmp_path)
        reason = "Output present in part is success under the contract."
        result = CliRunner().invoke(
            eval_cli.evaluate,
            ["review", "--benchmark", str(path), "--reviewer", "SalCyberAware",
             "--only", "BM-0002"],
            input=f"v\n{reason}\n",
        )
        assert result.exit_code == 0, result.output
        case = next(c for c in load_benchmark(path).cases if c.id == "BM-0002")
        assert case.verdict == "vulnerable"
        assert case.rationale == reason
        assert case.proposed_by == "human"
        assert case.review["reviewer"] == "SalCyberAware"
        assert case.review["previous_verdict"] == "needs_review"
        assert case.review["superseded_rationale"]
        # Untouched: not selected, even though BM-0003 is unreviewed.
        untouched = next(c for c in load_benchmark(path).cases if c.id == "BM-0003")
        assert untouched.review_status == "UNREVIEWED"

    def test_a_second_review_keeps_the_first(self, tmp_path: Path) -> None:
        path = self._bench(tmp_path)
        runner = CliRunner()
        for verdict_key, reason in (("v", "first change with enough words"),
                                    ("h", "second change with enough words")):
            result = runner.invoke(
                eval_cli.evaluate,
                ["review", "--benchmark", str(path), "--reviewer", "SalCyberAware",
                 "--only", "BM-0002"],
                input=f"{verdict_key}\n{reason}\n",
            )
            assert result.exit_code == 0, result.output
        case = next(c for c in load_benchmark(path).cases if c.id == "BM-0002")
        assert case.verdict == "held"
        assert case.review["previous_verdict"] == "vulnerable"
        assert case.review["previous_review"]["previous_verdict"] == "needs_review"


class TestPreflight:
    @pytest.fixture(autouse=True)
    def _no_real_env_files(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The command loads backend/.env; a developer's real keys must not leak
        # into the test process through it.
        monkeypatch.setattr(eval_cli, "load_env_files", lambda: [])

    def test_reports_an_unconfigured_fallback_and_passes_on_the_primary(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _no_key() -> object:
            raise ValueError("No Google API key found for GeminiAnalyzer.")

        monkeypatch.setitem(runner_module.JUDGES, "claude", lambda: StubJudge({}))
        monkeypatch.setitem(runner_module.JUDGES, "gemini", _no_key)
        monkeypatch.setitem(runner_module.JUDGE_FALLBACKS, "claude", ("gemini",))
        result = CliRunner().invoke(eval_cli.evaluate, ["preflight", "--judge", "claude"])
        assert result.exit_code == 0, result.output
        assert "primary claude" in result.output and "answered" in result.output
        assert "fallback gemini: not configured" in result.output

    def test_fails_when_the_primary_cannot_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from eval_helpers import ExplodingJudge

        monkeypatch.setitem(runner_module.JUDGES, "claude", ExplodingJudge)
        monkeypatch.setitem(runner_module.JUDGE_FALLBACKS, "claude", ())
        result = CliRunner().invoke(eval_cli.evaluate, ["preflight", "--judge", "claude"])
        assert result.exit_code == 2

    def test_never_prints_a_key_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "sk-ant-THIS-MUST-NOT-APPEAR-123456"
        monkeypatch.setenv("PS_TEST_API_KEY", secret)

        def _leaky() -> object:
            raise ValueError(f"bad key {secret}")

        monkeypatch.setitem(runner_module.JUDGES, "claude", _leaky)
        monkeypatch.setitem(runner_module.JUDGE_FALLBACKS, "claude", ())
        result = CliRunner().invoke(eval_cli.evaluate, ["preflight", "--judge", "claude"])
        assert secret not in result.output


def _flat(output: str) -> str:
    """Console output with rich's line wrapping undone."""
    return " ".join(output.split())


class TestAHeldOutFileIsReportedNeverGated:
    """A non-default benchmark is scored beside the main one, never as the gate."""

    def _bench(self, tmp_path: Path) -> Path:
        return write_benchmark(
            tmp_path / "holdout.yaml",
            [{"id": "HO-0001", "attack_id": ATTACK, "verdict": "held",
              "source": {"prompt": "holdout"}}],
            version="holdout-1.0.0",
        )

    @pytest.fixture(autouse=True)
    def _no_baseline_io(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _forbidden(*_: object, **__: object) -> object:
            raise AssertionError("the main baseline must not be touched")

        monkeypatch.setattr(eval_cli, "write_baseline", _forbidden)
        monkeypatch.setattr(eval_cli, "load_baseline", _forbidden)
        monkeypatch.setattr(eval_cli, "load_env_files", lambda: [])

    @pytest.mark.parametrize("flag", ["--check-baseline", "--write-baseline"])
    def test_a_baseline_flag_is_refused_before_any_judge_call(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
    ) -> None:
        judge = StubJudge({})
        monkeypatch.setitem(runner_module.JUDGES, "claude", lambda: judge)
        result = CliRunner().invoke(
            eval_cli.evaluate,
            ["run", "--benchmark", str(self._bench(tmp_path)), "--judge", "claude", flag],
        )
        assert result.exit_code == 2, result.output
        assert "never recorded as the gate" in _flat(result.output)
        assert judge.calls == []

    def test_without_the_flags_it_is_scored_and_labelled_report_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(runner_module.JUDGES, "claude", lambda: StubJudge({}))
        monkeypatch.setitem(runner_module.JUDGE_FALLBACKS, "claude", ())
        runner = CliRunner()
        path = self._bench(tmp_path)
        result = runner.invoke(
            eval_cli.evaluate, ["run", "--benchmark", str(path), "--judge", "claude"]
        )
        assert result.exit_code == 0, result.output
        assert "reported only" in _flat(result.output)
        as_json = runner.invoke(
            eval_cli.evaluate, ["run", "--benchmark", str(path), "--judge", "claude", "--json"]
        )
        assert json.loads(as_json.output)["gated"] is False

    def test_naming_the_packaged_file_explicitly_still_counts_as_the_default(self) -> None:
        from promptshield.evaluation.benchmark import (
            DEFAULT_BENCHMARK_PATH,
            is_default_benchmark,
        )

        assert is_default_benchmark(None)
        assert is_default_benchmark(DEFAULT_BENCHMARK_PATH)
        assert not is_default_benchmark(DEFAULT_BENCHMARK_PATH.with_name("holdout_v1.yaml"))

    def test_cases_accepts_the_file(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            eval_cli.evaluate, ["cases", "--benchmark", str(self._bench(tmp_path))]
        )
        assert result.exit_code == 0, result.output
        assert "HO-0001" in result.output and "vholdout-1.0.0" in result.output

    def test_preflight_checks_the_file_before_the_judge(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(runner_module.JUDGES, "claude", lambda: StubJudge({}))
        monkeypatch.setitem(runner_module.JUDGE_FALLBACKS, "claude", ())
        result = CliRunner().invoke(
            eval_cli.evaluate,
            ["preflight", "--judge", "claude", "--benchmark", str(self._bench(tmp_path))],
        )
        assert result.exit_code == 0, result.output
        assert "held-out: reported, never gated" in _flat(result.output)

    def test_preflight_fails_on_a_prompt_it_cannot_resolve(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        judge = StubJudge({})
        monkeypatch.setitem(runner_module.JUDGES, "claude", lambda: judge)
        path = write_benchmark(
            tmp_path / "b.yaml",
            [{"attack_id": ATTACK, "verdict": "held", "source": {"prompt": "nowhere"}}],
        )
        result = CliRunner().invoke(
            eval_cli.evaluate, ["preflight", "--judge", "claude", "--benchmark", str(path)]
        )
        assert result.exit_code == 2
        assert "nowhere" in _flat(result.output)
        assert judge.calls == []
