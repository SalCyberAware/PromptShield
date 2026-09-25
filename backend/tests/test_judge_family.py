"""OpenAI as the web cascade's third judge, never against its own family."""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest
import scan
from scan import build_web_analyzers, run_ensemble_judging

from promptshield.engines.base import BaseScanner
from promptshield.models import (
    AnalyzerVerdict,
    Attack,
    Scan,
    ScanStatus,
    TargetConfig,
    TargetType,
    Transcript,
)


def _mock_classes(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    classes: dict[str, MagicMock] = {}
    for module, cls, name in (
        ("claude_analyzer", "ClaudeAnalyzer", "claude_analyzer"),
        ("gemini_analyzer", "GeminiAnalyzer", "gemini_analyzer"),
        ("openai_analyzer", "OpenAIAnalyzer", "openai_analyzer"),
    ):
        mock = MagicMock()
        mock.return_value.name = name
        monkeypatch.setattr(f"promptshield.analyzers.{module}.{cls}", mock)
        classes[name] = mock
    return classes


class TestTheCascade:
    @pytest.mark.parametrize("target", ["gpt-4o-mini-2024-07-18", "gpt-oss:20b", "o3-mini"])
    def test_an_openai_target_never_gets_the_openai_judge(
        self, monkeypatch: pytest.MonkeyPatch, target: str
    ) -> None:
        classes = _mock_classes(monkeypatch)
        analyzers = build_web_analyzers(target)
        assert [a.name for a in analyzers] == ["claude_analyzer", "gemini_analyzer"]
        classes["openai_analyzer"].assert_not_called()

    def test_the_default_target_is_openai_so_the_default_cascade_is_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock_classes(monkeypatch)
        assert [a.name for a in build_web_analyzers()] == ["claude_analyzer", "gemini_analyzer"]

    def test_a_llama_target_gets_openai_third(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_classes(monkeypatch)
        assert [a.name for a in build_web_analyzers("llama3.2:3b")] == [
            "claude_analyzer", "gemini_analyzer", "openai_analyzer",
        ]

    def test_the_deployment_target_decides_when_none_is_passed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock_classes(monkeypatch)
        monkeypatch.setenv("PROMPTSHIELD_TARGET_MODEL", "llama3.2:3b")
        assert build_web_analyzers()[-1].name == "openai_analyzer"

    def test_ensemble_mode_never_adds_the_openai_tier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Thorough mode is two cross-provider opinions, not three."""
        judges = []
        for name in ("claude_analyzer", "gemini_analyzer", "openai_analyzer"):
            judge = MagicMock()
            judge.name = name

            async def _analyze(attack: Any, response: str, _n: str = name) -> AnalyzerVerdict:
                return AnalyzerVerdict(analyzer_name=_n, success=False, confidence_score=0.9)

            judge.analyze = _analyze
            judges.append(judge)
        monkeypatch.setattr(scan, "build_web_analyzers", lambda: judges)
        attack = scan.load_web_demo_attacks()[0]
        s = Scan(
            scan_id="web-x",
            target=TargetConfig(url="internal://llama3.2:3b", target_type=TargetType.SYSTEM_PROMPT),
            status=ScanStatus.COMPLETED,
            transcripts=[Transcript(
                attack_id=attack.id, attack_name=attack.name,
                owasp_category=attack.owasp_category, severity=attack.severity,
                prompt=attack.prompt, response="a reply",
            )],
            library_version="1.4.0",
        )
        verdicts = asyncio.run(run_ensemble_judging(s))
        assert [v["analyzer"] for v in verdicts[attack.id]] == ["claude_analyzer", "gemini_analyzer"]


class _OneReplyScanner(BaseScanner):
    async def send_attack(self, attack: Attack) -> str | None:
        return "Sure, here is a reply."

    async def cleanup(self) -> None:
        pass


class _Judge:
    def __init__(self, name: str, behaviour: str) -> None:
        self.name = name
        self.model = f"{name}-model"
        self.behaviour = behaviour
        self.calls = 0

    async def analyze(self, attack: Attack, response: str, system_prompt: str | None = None) -> AnalyzerVerdict:
        self.calls += 1
        if self.behaviour == "raise":
            raise RuntimeError("503 UNAVAILABLE")
        if self.behaviour == "refuse":
            return AnalyzerVerdict(
                analyzer_name=self.name, success=False, confidence_score=0.0,
                reasoning="Judge declined to answer: the API refused to generate a verdict.",
            )
        return AnalyzerVerdict(
            analyzer_name=self.name, success=False, confidence_score=0.9, reasoning="held"
        )


class TestAScanReachesOpenAIOnlyWhenAllowed:
    def _run(self, monkeypatch: pytest.MonkeyPatch, target: str) -> tuple[Scan, _Judge]:
        claude = _Judge("claude_analyzer", "refuse")
        gemini = _Judge("gemini_analyzer", "raise")
        openai = _Judge("openai_analyzer", "answer")
        by_name = {"claude_analyzer": claude, "gemini_analyzer": gemini, "openai_analyzer": openai}
        for module, cls, name in (
            ("claude_analyzer", "ClaudeAnalyzer", "claude_analyzer"),
            ("gemini_analyzer", "GeminiAnalyzer", "gemini_analyzer"),
            ("openai_analyzer", "OpenAIAnalyzer", "openai_analyzer"),
        ):
            monkeypatch.setattr(
                f"promptshield.analyzers.{module}.{cls}",
                lambda *a, _j=by_name[name], **k: _j,
            )
        attack = scan.load_web_demo_attacks()[0]
        scanner = _OneReplyScanner(
            TargetConfig(url=f"internal://{target}", target_type=TargetType.SYSTEM_PROMPT,
                         rate_limit=6000),
            [attack],
        )
        result = asyncio.run(
            scanner.run_scan("web-t", analyzers=build_web_analyzers(target))
        )
        return result, openai

    def test_a_llama_target_reaches_openai_after_claude_refuses_and_gemini_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, openai = self._run(monkeypatch, "llama3.2:3b")
        assert openai.calls == 1
        assert result.transcripts[0].analyzers_run == ["pattern_analyzer", "openai_analyzer"]
        assert result.provenance is not None
        assert result.provenance.judge_models == {"openai_analyzer": "openai_analyzer-model"}

    def test_an_openai_target_never_does(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result, openai = self._run(monkeypatch, "gpt-4o-mini-2024-07-18")
        assert openai.calls == 0
        assert result.transcripts[0].analyzers_run == ["pattern_analyzer"]
        assert result.provenance is not None
        assert result.provenance.judge_models == {}
