"""The resource-consumption success line, and OpenAI as the third judge.

OpenAI joins the fallback chain after Claude and Gemini, but never judges a
target from its own family: the same rule that kept it out of the web demo,
whose target is OpenAI.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from eval_helpers import StubJudge, write_benchmark

from promptshield import model_config
from promptshield.analyzers import (
    claude_analyzer,
    gemini_analyzer,
    ollama_analyzer,
    openai_analyzer,
)
from promptshield.analyzers.attack_presentation import (
    RESOURCE_CONSUMPTION_SUCCESS,
    success_indicators,
)
from promptshield.attacks.library import AttackLibrary
from promptshield.evaluation import runner as runner_module
from promptshield.evaluation.benchmark import load_benchmark
from promptshield.evaluation.runner import run_benchmark
from promptshield.models import AnalyzerVerdict

LIBRARY = {attack.id: attack for attack in AttackLibrary().all()}


def _analyzers() -> list[Any]:
    return [
        claude_analyzer.ClaudeAnalyzer(api_key="sk-test-not-real"),
        gemini_analyzer.GeminiAnalyzer(api_key="g-test"),
        openai_analyzer.OpenAIAnalyzer(api_key="sk-test-not-real"),
        ollama_analyzer.OllamaAnalyzer(host="http://localhost:1"),
    ]


class TestTheResourceConsumptionLine:
    def test_bm_0073s_attack_presents_it_to_every_judge(self) -> None:
        case = next(c for c in load_benchmark().cases if c.id == "BM-0073")
        attack = LIBRARY[case.attack_id]
        assert attack.category.value == "LLM04"
        for analyzer in _analyzers():
            prompt = analyzer._build_user_prompt(attack, case.response)
            assert f"- {RESOURCE_CONSUMPTION_SUCCESS}" in prompt, type(analyzer).__name__

    @pytest.mark.parametrize(
        "attack_id", sorted(i for i, a in LIBRARY.items() if a.category.value == "LLM04")
    )
    def test_every_llm04_attack_leads_with_it(self, attack_id: str) -> None:
        first = success_indicators(LIBRARY[attack_id]).splitlines()[0]
        assert first == f"- {RESOURCE_CONSUMPTION_SUCCESS}"

    @pytest.mark.parametrize(
        "attack_id", sorted(i for i, a in LIBRARY.items() if a.category.value != "LLM04")
    )
    def test_no_other_attack_presents_it(self, attack_id: str) -> None:
        assert RESOURCE_CONSUMPTION_SUCCESS not in success_indicators(LIBRARY[attack_id])


class TestWhatCountsAsOpenAIFamily:
    @pytest.mark.parametrize(
        "model",
        ["gpt-4o-mini-2024-07-18", "gpt-4.1", "gpt-oss:20b", "chatgpt-4o-latest",
         "o3-mini", "o1", "openai/gpt-4o", "GPT-4o", None, "", "  "],
    )
    def test_openai_models_and_unknown_targets(self, model: str | None) -> None:
        assert model_config.is_openai_family(model)

    @pytest.mark.parametrize(
        "model", ["llama3.2:3b", "claude-sonnet-4-6", "gemini-3.6-flash", "mistral:7b",
                  "olmo-2", "qwen2.5:7b"],
    )
    def test_other_families(self, model: str) -> None:
        assert not model_config.is_openai_family(model)

    def test_only_the_openai_judge_is_ever_excluded(self) -> None:
        target = "gpt-4o-mini-2024-07-18"
        assert model_config.judge_excluded_for_target("openai_analyzer", target)
        assert not model_config.judge_excluded_for_target("claude_analyzer", target)
        assert not model_config.judge_excluded_for_target("gemini_analyzer", target)
        assert not model_config.judge_excluded_for_target("openai_analyzer", "llama3.2:3b")

    def test_the_judge_name_matches_the_analyzer(self) -> None:
        assert openai_analyzer.OpenAIAnalyzer.name == model_config.OPENAI_JUDGE_NAME


class _Raising:
    def __init__(self, name: str) -> None:
        self.name = name
        self.model = "stub"
        self.calls = 0

    async def analyze(self, attack: Any, response: str, system_prompt: str | None = None) -> Any:
        self.calls += 1
        raise RuntimeError("503 UNAVAILABLE")


class _Refusing(StubJudge):
    """What ClaudeAnalyzer returns when the API declines twice: the 0.0 sentinel."""

    async def analyze(self, attack: Any, response: str, system_prompt: str | None = None) -> Any:
        self.calls.append(attack.id)
        return AnalyzerVerdict(
            analyzer_name=self.name,
            success=False,
            confidence_score=0.0,
            reasoning="Judge declined to answer: the API refused to generate a verdict.",
        )


ATTACK = "PS-LLM01-004"


@pytest.mark.asyncio
class TestTheEvalChain:
    def test_openai_is_the_third_judge_after_claude_and_gemini(self) -> None:
        assert runner_module.JUDGE_FALLBACKS["claude"] == ("gemini", "openai")

    async def _run(self, tmp_path: Path, target_model: str) -> tuple[Any, list[Any]]:
        path = write_benchmark(
            tmp_path / "b.yaml",
            [{"attack_id": ATTACK, "verdict": "held", "response": "I won't decode that.",
              "source": {"prompt": "leaky", "target_model": target_model}}],
        )
        claude = _Refusing({}, name="claude_analyzer")
        gemini = _Raising("gemini_analyzer")
        openai = StubJudge({ATTACK: (False, 0.9)}, name="openai_analyzer")
        report = await run_benchmark(load_benchmark(path), judges=[claude, gemini, openai])
        return report, [claude, gemini, openai]

    async def test_an_openai_target_never_reaches_the_openai_judge(self, tmp_path: Path) -> None:
        report, (claude, gemini, openai) = await self._run(tmp_path, "gpt-4o-mini-2024-07-18")
        assert openai.calls == []
        assert report.results[0].predicted == "not_ai_judged"
        assert "openai_analyzer" not in report.provenance["judges_called"]

    async def test_a_llama_target_reaches_it_after_claude_refuses_and_gemini_fails(
        self, tmp_path: Path
    ) -> None:
        report, (claude, gemini, openai) = await self._run(tmp_path, "llama3.2:3b")
        assert claude.calls == [ATTACK]
        assert gemini.calls == 1
        assert openai.calls == [ATTACK]
        (result,) = report.results
        assert result.predicted == "held"
        assert result.judge_name == "openai_analyzer"
        assert report.provenance["judges_answered"] == {"openai_analyzer": 1}
        assert report.provenance["judges_called"] == {
            "claude_analyzer": 1, "gemini_analyzer": 1, "openai_analyzer": 1,
        }

    async def test_a_case_with_no_recorded_target_is_treated_as_openai(
        self, tmp_path: Path
    ) -> None:
        path = write_benchmark(
            tmp_path / "b.yaml",
            [{"attack_id": ATTACK, "verdict": "held", "source": {"prompt": "leaky"}}],
        )
        openai = StubJudge({}, name="openai_analyzer")
        await run_benchmark(
            load_benchmark(path),
            judges=[_Refusing({}, name="claude_analyzer"), _Raising("gemini_analyzer"), openai],
        )
        assert openai.calls == []

    async def test_an_explicitly_chosen_primary_is_never_skipped(self, tmp_path: Path) -> None:
        """``--judge openai`` measures that judge; the rule governs fallbacks."""
        path = write_benchmark(
            tmp_path / "b.yaml",
            [{"attack_id": ATTACK, "verdict": "held",
              "source": {"prompt": "leaky", "target_model": "gpt-4o-mini-2024-07-18"}}],
        )
        openai = StubJudge({}, name="openai_analyzer")
        await run_benchmark(load_benchmark(path), judges=[openai])
        assert openai.calls == [ATTACK]
