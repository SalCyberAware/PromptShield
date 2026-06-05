"""Tests for the BaseScanner orchestration and verdict-combining logic."""
from __future__ import annotations

from collections.abc import Sequence
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from promptshield.engines.base import (
    MAX_TRANSCRIPT_RESPONSE_CHARS,
    BaseScanner,
    _combine_verdicts,
)
from promptshield.models import (
    AnalyzerVerdict,
    Attack,
    AuthType,
    Confidence,
    ScanStatus,
    TargetConfig,
    TargetType,
)

# 60 / 6000 = 0.01s of asyncio.sleep between attacks — keeps tests fast without
# changing any production logic.
FAST_RATE_LIMIT = 6000


def _target(rate_limit: int = FAST_RATE_LIMIT) -> TargetConfig:
    return TargetConfig(
        url="https://api.example.com/v1/messages",
        target_type=TargetType.API,
        auth_type=AuthType.NONE,
        rate_limit=rate_limit,
    )


class _FakeScanner(BaseScanner):
    """Concrete BaseScanner subclass that returns canned responses."""

    def __init__(
        self,
        target: TargetConfig,
        attacks: list[Attack],
        responses: Sequence[str | None] = (),
    ) -> None:
        super().__init__(target, attacks)
        self._responses = list(responses)
        self.cleanup_called = False

    async def send_attack(self, attack: Attack) -> str | None:
        if not self._responses:
            return ""
        return self._responses.pop(0)

    async def cleanup(self) -> None:
        self.cleanup_called = True


class _RaisingScanner(BaseScanner):
    """Concrete scanner whose send_attack always raises."""

    async def send_attack(self, attack: Attack) -> str | None:
        raise RuntimeError("simulated send failure")

    async def cleanup(self) -> None:
        pass


# =============================================================================
# _combine_verdicts: pure logic, no async
# =============================================================================


class TestCombineVerdictsEdgeCases:
    """Empty-list and boost-cap branches."""

    def test_empty_verdicts_returns_low_with_review(self) -> None:
        success, score, conf, review = _combine_verdicts([])
        assert success is False
        assert score == 0.0
        assert conf == Confidence.LOW
        assert review is True

    def test_confidence_boost_is_capped_at_098(self) -> None:
        # Single agreeing verdict at 0.99: 0.99 + 0.1 = 1.09 -> capped at 0.98.
        verdicts = [
            AnalyzerVerdict(analyzer_name="a1", success=True, confidence_score=0.99),
        ]
        _, score, _, _ = _combine_verdicts(verdicts)
        assert score == pytest.approx(0.98)


class TestCombineVerdictsAllAgreeSuccess:
    """All analyzers say the attack succeeded — three confidence sub-tiers."""

    def test_high_scores_yield_high_confidence_no_review(self) -> None:
        verdicts = [
            AnalyzerVerdict(analyzer_name="a1", success=True, confidence_score=0.9),
            AnalyzerVerdict(analyzer_name="a2", success=True, confidence_score=0.9),
        ]
        success, score, conf, review = _combine_verdicts(verdicts)
        assert success is True
        assert conf == Confidence.HIGH
        assert review is False
        # avg(0.9, 0.9) + 0.1 = 1.0, capped at 0.98
        assert score == pytest.approx(0.98)

    def test_medium_scores_yield_medium_confidence_no_review(self) -> None:
        verdicts = [
            AnalyzerVerdict(analyzer_name="a1", success=True, confidence_score=0.65),
            AnalyzerVerdict(analyzer_name="a2", success=True, confidence_score=0.65),
        ]
        success, score, conf, review = _combine_verdicts(verdicts)
        assert success is True
        # avg=0.65 -> boosted=0.75 -> >=0.7 -> MEDIUM
        assert conf == Confidence.MEDIUM
        assert review is False
        assert score == pytest.approx(0.75)

    def test_low_scores_yield_low_confidence_with_review(self) -> None:
        verdicts = [
            AnalyzerVerdict(analyzer_name="a1", success=True, confidence_score=0.4),
            AnalyzerVerdict(analyzer_name="a2", success=True, confidence_score=0.5),
        ]
        success, score, conf, review = _combine_verdicts(verdicts)
        assert success is True
        # avg=0.45 -> boosted=0.55 -> < 0.7 -> LOW with review
        assert conf == Confidence.LOW
        assert review is True


class TestCombineVerdictsDisagreement:
    """Analyzers disagree on whether the attack succeeded."""

    def test_disagreement_yields_success_with_low_confidence_and_review(self) -> None:
        verdicts = [
            AnalyzerVerdict(analyzer_name="pattern", success=False, confidence_score=0.8),
            AnalyzerVerdict(analyzer_name="claude", success=True, confidence_score=0.9),
        ]
        success, score, conf, review = _combine_verdicts(verdicts)
        assert success is True
        assert conf == Confidence.LOW
        assert review is True
        # Only success verdicts contribute to score: 0.9 * 0.6 = 0.54
        assert score == pytest.approx(0.54)

    def test_disagreement_score_uses_success_avg_only(self) -> None:
        verdicts = [
            AnalyzerVerdict(analyzer_name="a1", success=True, confidence_score=0.95),
            AnalyzerVerdict(analyzer_name="a2", success=True, confidence_score=0.95),
            AnalyzerVerdict(analyzer_name="a3", success=False, confidence_score=0.5),
        ]
        _, score, _, _ = _combine_verdicts(verdicts)
        # success_avg = (0.95 + 0.95) / 2 = 0.95; score = 0.95 * 0.6 = 0.57
        assert score == pytest.approx(0.57)


class TestCombineVerdictsAllAgreeFail:
    """All analyzers say the attack failed."""

    def test_all_fail_yields_no_finding_no_review(self) -> None:
        verdicts = [
            AnalyzerVerdict(analyzer_name="a1", success=False, confidence_score=0.7),
            AnalyzerVerdict(analyzer_name="a2", success=False, confidence_score=0.6),
        ]
        success, score, conf, review = _combine_verdicts(verdicts)
        assert success is False
        assert score == 0.0
        assert conf == Confidence.LOW
        assert review is False


# =============================================================================
# BaseScanner.run_scan lifecycle and orchestration
# =============================================================================


class TestRunScanLifecycle:
    """Status transitions, timing fields, cleanup invocation."""

    async def test_status_is_completed_on_normal_completion(
        self, sample_attack_llm01: Attack
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["plain response"])
        scan = await scanner.run_scan(scan_id="SCAN-OK")
        assert scan.status == ScanStatus.COMPLETED

    async def test_started_at_and_completed_at_are_both_set(
        self, sample_attack_llm01: Attack
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["plain response"])
        scan = await scanner.run_scan(scan_id="SCAN-TIMES")
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert scan.completed_at >= scan.started_at

    async def test_cleanup_called_on_normal_completion(
        self, sample_attack_llm01: Attack
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["plain response"])
        await scanner.run_scan(scan_id="SCAN-CLEAN")
        assert scanner.cleanup_called is True

    async def test_failed_status_when_outer_exception_propagates(
        self, sample_attack_llm01: Attack
    ) -> None:
        """An exception in on_progress (which runs outside the inner try)
        propagates to the outer except block and yields ScanStatus.FAILED."""
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["plain response"])

        def bad_progress(current: int, total: int, attack: Attack) -> None:
            raise RuntimeError("progress callback exploded")

        scan = await scanner.run_scan(scan_id="SCAN-BOOM", on_progress=bad_progress)
        assert scan.status == ScanStatus.FAILED
        assert "progress callback exploded" in (scan.error or "")

    async def test_cleanup_called_even_on_outer_exception(
        self, sample_attack_llm01: Attack
    ) -> None:
        """The finally block must run cleanup() even when the scan fails."""
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["plain response"])

        def bad_progress(current: int, total: int, attack: Attack) -> None:
            raise RuntimeError("boom")

        await scanner.run_scan(scan_id="S", on_progress=bad_progress)
        assert scanner.cleanup_called is True

    async def test_scan_id_and_library_version_preserved(
        self, sample_attack_llm01: Attack
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["response"])
        scan = await scanner.run_scan(scan_id="SCAN-CUSTOM", library_version="2.5.0")
        assert scan.scan_id == "SCAN-CUSTOM"
        assert scan.library_version == "2.5.0"


class TestRunScanAnalyzerWiring:
    """Which analyzers run under which conditions."""

    async def test_pattern_analyzer_always_runs_on_valid_response(
        self, sample_attack_llm01: Attack, clean_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [clean_response_llm01])
        scan = await scanner.run_scan(scan_id="S")
        assert scan.transcripts[0].analyzers_run == ["pattern_analyzer"]
        assert scan.analyzers_used == ["pattern_analyzer"]

    async def test_ai_analyzer_does_not_run_when_disabled(
        self, sample_attack_llm01: Attack, clean_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [clean_response_llm01])
        scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=False)
        assert "claude_analyzer" not in scan.analyzers_used

    async def test_ai_analyzer_runs_when_enabled_and_available(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        mock_verdict = AnalyzerVerdict(
            analyzer_name="claude_analyzer",
            success=True,
            confidence_score=0.92,
            reasoning="Mocked: attack succeeded.",
        )
        mock_instance = MagicMock()
        mock_instance.analyze = AsyncMock(return_value=mock_verdict)
        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer",
            return_value=mock_instance,
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        assert "claude_analyzer" in scan.analyzers_used
        mock_instance.analyze.assert_awaited_once()

    async def test_ai_analyzer_value_error_at_init_is_captured(
        self, sample_attack_llm01: Attack, clean_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [clean_response_llm01])
        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer",
            side_effect=ValueError("no API key configured"),
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        assert scan.status == ScanStatus.COMPLETED
        assert any("AI analyzer disabled" in err for err in scanner.errors)
        assert "claude_analyzer" not in scan.analyzers_used

    async def test_ai_analyzer_import_error_at_init_is_captured(
        self, sample_attack_llm01: Attack, clean_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [clean_response_llm01])
        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer",
            side_effect=ImportError("anthropic package not installed"),
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        assert scan.status == ScanStatus.COMPLETED
        assert any("AI analyzer disabled" in err for err in scanner.errors)

    async def test_ai_analyzer_per_attack_failure_is_captured(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        mock_instance = MagicMock()
        mock_instance.analyze = AsyncMock(side_effect=RuntimeError("Claude API blew up"))
        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer",
            return_value=mock_instance,
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        # Scan still completes; per-attack AI failures are captured to errors.
        assert scan.status == ScanStatus.COMPLETED
        assert any("Claude API blew up" in err for err in scanner.errors)


def _mock_ai_analyzer(name: str, verdict: AnalyzerVerdict | None = None,
                      side_effect: BaseException | None = None) -> MagicMock:
    """Build a MagicMock that quacks like an AI analyzer instance.

    Either ``verdict`` is returned from ``analyze()``, or ``side_effect`` is
    raised. The ``name`` attribute is set so the orchestrator can read it for
    error messages and ``analyzers_used`` tracking.
    """
    instance = MagicMock()
    instance.name = name
    if side_effect is not None:
        instance.analyze = AsyncMock(side_effect=side_effect)
    else:
        instance.analyze = AsyncMock(return_value=verdict)
    return instance


class TestRunScanAIFallbackChain:
    """Claude → OpenAI cascading-fallback behavior at the orchestration layer."""

    async def test_claude_succeeds_openai_never_called(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        """Happy path: primary analyzer wins, fallback stays untouched."""
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        claude_verdict = AnalyzerVerdict(
            analyzer_name="claude_analyzer",
            success=True,
            confidence_score=0.92,
            reasoning="Claude detected leak.",
        )
        claude = _mock_ai_analyzer("claude_analyzer", verdict=claude_verdict)
        openai = _mock_ai_analyzer(
            "openai_analyzer",
            verdict=AnalyzerVerdict(
                analyzer_name="openai_analyzer",
                success=False,
                confidence_score=0.5,
                reasoning="(unused)",
            ),
        )

        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer", return_value=claude
        ), patch(
            "promptshield.analyzers.openai_analyzer.OpenAIAnalyzer", return_value=openai
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        claude.analyze.assert_awaited_once()
        openai.analyze.assert_not_awaited()
        assert "claude_analyzer" in scan.analyzers_used
        assert "openai_analyzer" not in scan.analyzers_used

    async def test_claude_raises_falls_back_to_openai(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        """Primary raises, fallback succeeds, fallback's verdict is recorded."""
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        claude = _mock_ai_analyzer(
            "claude_analyzer", side_effect=RuntimeError("Claude API blew up")
        )
        openai_verdict = AnalyzerVerdict(
            analyzer_name="openai_analyzer",
            success=True,
            confidence_score=0.88,
            reasoning="GPT confirmed credential leak.",
        )
        openai = _mock_ai_analyzer("openai_analyzer", verdict=openai_verdict)

        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer", return_value=claude
        ), patch(
            "promptshield.analyzers.openai_analyzer.OpenAIAnalyzer", return_value=openai
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        claude.analyze.assert_awaited_once()
        openai.analyze.assert_awaited_once()
        assert any("Claude API blew up" in err for err in scanner.errors)
        assert "openai_analyzer" in scan.analyzers_used
        # Claude never produced a verdict, so it isn't listed as actually used.
        assert "claude_analyzer" not in scan.analyzers_used
        # The OpenAI verdict made it into the finding's analyzer_verdicts list.
        assert len(scan.findings) == 1
        verdict_names = {v.analyzer_name for v in scan.findings[0].analyzer_verdicts}
        assert "openai_analyzer" in verdict_names

    async def test_claude_returns_error_verdict_falls_back_to_openai(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        """0.0-confidence verdict (auth/network/parse failure) triggers fallback."""
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        claude_error_verdict = AnalyzerVerdict(
            analyzer_name="claude_analyzer",
            success=False,
            confidence_score=0.0,
            reasoning="Analyzer error: 401 Unauthorized",
        )
        claude = _mock_ai_analyzer("claude_analyzer", verdict=claude_error_verdict)
        openai_verdict = AnalyzerVerdict(
            analyzer_name="openai_analyzer",
            success=True,
            confidence_score=0.81,
            reasoning="GPT picked it up.",
        )
        openai = _mock_ai_analyzer("openai_analyzer", verdict=openai_verdict)

        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer", return_value=claude
        ), patch(
            "promptshield.analyzers.openai_analyzer.OpenAIAnalyzer", return_value=openai
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        claude.analyze.assert_awaited_once()
        openai.analyze.assert_awaited_once()
        assert any(
            "claude_analyzer returned error verdict" in err for err in scanner.errors
        )
        assert "openai_analyzer" in scan.analyzers_used

    async def test_both_ai_analyzers_fail_pattern_only_result(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        """When primary AND fallback fail, the scan continues pattern-only."""
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        claude = _mock_ai_analyzer(
            "claude_analyzer", side_effect=RuntimeError("Claude blew up")
        )
        openai = _mock_ai_analyzer(
            "openai_analyzer", side_effect=RuntimeError("OpenAI blew up too")
        )

        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer", return_value=claude
        ), patch(
            "promptshield.analyzers.openai_analyzer.OpenAIAnalyzer", return_value=openai
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        assert scan.status == ScanStatus.COMPLETED
        assert any("Claude blew up" in err for err in scanner.errors)
        assert any("OpenAI blew up too" in err for err in scanner.errors)
        # Neither AI analyzer produced a verdict, so neither appears.
        assert scan.analyzers_used == ["pattern_analyzer"]
        # The pattern analyzer still detected the attack on its own.
        assert len(scan.findings) == 1
        verdict_names = {v.analyzer_name for v in scan.findings[0].analyzer_verdicts}
        assert verdict_names == {"pattern_analyzer"}

    async def test_claude_init_fails_openai_promoted_to_primary(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        """If Claude's __init__ raises, OpenAI is promoted to primary AI analyzer."""
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        openai_verdict = AnalyzerVerdict(
            analyzer_name="openai_analyzer",
            success=True,
            confidence_score=0.79,
            reasoning="GPT verdict.",
        )
        openai = _mock_ai_analyzer("openai_analyzer", verdict=openai_verdict)

        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer",
            side_effect=ValueError("no Anthropic key"),
        ), patch(
            "promptshield.analyzers.openai_analyzer.OpenAIAnalyzer", return_value=openai
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        openai.analyze.assert_awaited_once()
        assert any(
            "AI analyzer disabled (claude_analyzer)" in err for err in scanner.errors
        )
        assert "openai_analyzer" in scan.analyzers_used
        assert "claude_analyzer" not in scan.analyzers_used


class TestRunScanFindings:
    """When findings are and aren't created, and what they contain."""

    async def test_no_finding_when_response_is_clean(
        self, sample_attack_llm01: Attack, clean_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [clean_response_llm01])
        scan = await scanner.run_scan(scan_id="S")
        assert len(scan.findings) == 0

    async def test_finding_created_when_pattern_analyzer_says_success(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        scan = await scanner.run_scan(scan_id="S")
        assert len(scan.findings) == 1
        finding = scan.findings[0]
        assert finding.attack_id == sample_attack_llm01.id
        assert finding.severity == sample_attack_llm01.severity
        assert finding.target_url == scanner.target.url

    async def test_finding_evidence_contains_prompt_and_response(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        scan = await scanner.run_scan(scan_id="S")
        finding = scan.findings[0]
        assert finding.evidence["attack_prompt"] == sample_attack_llm01.prompt
        assert successful_response_llm01 in finding.evidence["response_snippet"]
        assert finding.evidence["owasp_category"] == sample_attack_llm01.owasp_category
        assert finding.evidence["mitre_atlas"] == sample_attack_llm01.mitre_atlas

    async def test_finding_evidence_flags_analyzer_agreement(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        mock_verdict = AnalyzerVerdict(
            analyzer_name="claude_analyzer",
            success=True,
            confidence_score=0.85,
            reasoning="Claude agrees.",
        )
        mock_instance = MagicMock()
        mock_instance.analyze = AsyncMock(return_value=mock_verdict)
        with patch(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer",
            return_value=mock_instance,
        ):
            scan = await scanner.run_scan(scan_id="S", use_ai_analyzer=True)

        finding = scan.findings[0]
        assert finding.evidence["analyzers_agreed"] is True
        assert len(finding.analyzer_verdicts) == 2

    async def test_no_finding_for_error_response(
        self, sample_attack_llm01: Attack
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["[ERROR] Connection refused"])
        scan = await scanner.run_scan(scan_id="S")
        assert len(scan.findings) == 0
        # The attack still counts as run.
        assert scan.attacks_run == 1

    async def test_no_finding_for_timeout_response(
        self, sample_attack_llm01: Attack
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], ["[TIMEOUT]"])
        scan = await scanner.run_scan(scan_id="S")
        assert len(scan.findings) == 0
        assert scan.attacks_run == 1


class TestRunScanTranscripts:
    """Transcript recording, truncation, and finding linkage."""

    async def test_transcripts_saved_by_default(
        self, sample_attack_llm01: Attack, clean_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [clean_response_llm01])
        scan = await scanner.run_scan(scan_id="S")
        assert len(scan.transcripts) == 1
        t = scan.transcripts[0]
        assert t.attack_id == sample_attack_llm01.id
        assert t.prompt == sample_attack_llm01.prompt
        assert t.response == clean_response_llm01
        assert t.response_truncated is False
        assert t.became_finding is False

    async def test_transcripts_skipped_when_disabled(
        self, sample_attack_llm01: Attack, clean_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [clean_response_llm01])
        scan = await scanner.run_scan(scan_id="S", save_transcripts=False)
        assert len(scan.transcripts) == 0

    async def test_transcript_response_truncated_above_max(
        self, sample_attack_llm01: Attack
    ) -> None:
        big_response = "A" * (MAX_TRANSCRIPT_RESPONSE_CHARS + 1000)
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [big_response])
        scan = await scanner.run_scan(scan_id="S")
        t = scan.transcripts[0]
        assert t.response_truncated is True
        assert len(t.response) == MAX_TRANSCRIPT_RESPONSE_CHARS

    async def test_transcript_records_finding_link_when_attack_succeeded(
        self, sample_attack_llm01: Attack, successful_response_llm01: str
    ) -> None:
        scanner = _FakeScanner(_target(), [sample_attack_llm01], [successful_response_llm01])
        scan = await scanner.run_scan(scan_id="S")
        finding = scan.findings[0]
        transcript = scan.transcripts[0]
        assert transcript.became_finding is True
        assert transcript.finding_id == finding.finding_id


class TestRunScanProgress:
    """The on_progress callback wiring."""

    async def test_progress_callback_invoked_once_per_attack(
        self, sample_attacks: list[Attack]
    ) -> None:
        # sample_attacks fixture has 2 attacks.
        scanner = _FakeScanner(_target(), sample_attacks, ["resp1", "resp2"])
        calls: list[tuple[int, int, str]] = []

        def record(current: int, total: int, attack: Attack) -> None:
            calls.append((current, total, attack.id))

        await scanner.run_scan(scan_id="S", on_progress=record)
        assert len(calls) == 2
        assert calls[0][0] == 1 and calls[0][1] == 2
        assert calls[1][0] == 2 and calls[1][1] == 2


class TestRunScanErrorHandling:
    """Error propagation from send_attack and from None responses."""

    async def test_send_attack_exception_is_caught_and_recorded(
        self, sample_attack_llm01: Attack
    ) -> None:
        scanner = _RaisingScanner(_target(), [sample_attack_llm01])
        scan = await scanner.run_scan(scan_id="S")
        # Per-attack exceptions are swallowed by the inner try.
        assert scan.status == ScanStatus.COMPLETED
        assert len(scanner.errors) == 1
        assert "simulated send failure" in scanner.errors[0]
        # The attack still counts as run.
        assert scan.attacks_run == 1

    async def test_send_attack_none_response_handled_gracefully(
        self, sample_attack_llm01: Attack
    ) -> None:
        """send_attack returns None - coerced to empty string in run_scan."""

        class _NoneScanner(BaseScanner):
            async def send_attack(self, attack: Attack) -> str | None:
                return None

            async def cleanup(self) -> None:
                pass

        scanner = _NoneScanner(_target(), [sample_attack_llm01])
        scan = await scanner.run_scan(scan_id="S")
        assert scan.status == ScanStatus.COMPLETED
        assert scan.attacks_run == 1
        assert scan.transcripts[0].response == ""
