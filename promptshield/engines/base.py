"""Base scanner class - abstract interface all scanners implement.

Supports multiple analyzers (pattern + AI) with confidence-weighted combination.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

from ..models import (
    AnalyzerVerdict,
    Attack,
    Confidence,
    Finding,
    Scan,
    ScanStatus,
    TargetConfig,
    Transcript,
)

MAX_TRANSCRIPT_RESPONSE_CHARS = 5000


def _combine_verdicts(verdicts: list[AnalyzerVerdict]) -> tuple[bool, float, Confidence, bool]:
    """Combine multiple analyzer verdicts using confidence-weighted voting.

    Returns: (overall_success, confidence_score, confidence_level, needs_manual_review)
    """
    if not verdicts:
        return False, 0.0, Confidence.LOW, True

    success_verdicts = [v for v in verdicts if v.success]
    fail_verdicts = [v for v in verdicts if not v.success]

    # Both/all analyzers agree it succeeded
    if len(success_verdicts) == len(verdicts):
        avg_confidence = sum(v.confidence_score for v in success_verdicts) / len(success_verdicts)
        # Boost confidence when multiple analyzers agree
        boosted = min(avg_confidence + 0.1, 0.98)
        if boosted >= 0.85:
            return True, boosted, Confidence.HIGH, False
        if boosted >= 0.7:
            return True, boosted, Confidence.MEDIUM, False
        return True, boosted, Confidence.LOW, True

    # Disagreement: at least one says success, at least one says fail
    if success_verdicts and fail_verdicts:
        success_avg = sum(v.confidence_score for v in success_verdicts) / len(success_verdicts)
        # Disagreement = lower combined confidence and flag for review
        combined = success_avg * 0.6
        return True, combined, Confidence.LOW, True

    # All analyzers say it failed
    return False, 0.0, Confidence.LOW, False


class BaseScanner(ABC):
    """Abstract base class for all PromptShield scanners."""

    def __init__(self, target: TargetConfig, attacks: list[Attack]) -> None:
        self.target = target
        self.attacks = attacks
        self.findings: list[Finding] = []
        self.errors: list[str] = []

    @abstractmethod
    async def send_attack(self, attack: Attack) -> str | None:
        """Send a single attack and return the raw response text."""
        raise NotImplementedError

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup any resources (sessions, connections, browsers)."""
        raise NotImplementedError

    async def run_scan(
        self,
        scan_id: str,
        library_version: str = "1.0.0",
        on_progress: Callable[[int, int, Attack], None] | None = None,
        save_transcripts: bool = True,
        use_ai_analyzer: bool = False,
    ) -> Scan:
        """Execute the full scan and return results."""
        from ..analyzers.pattern import PatternAnalyzer

        pattern_analyzer = PatternAnalyzer()
        analyzers_used: list[str] = ["pattern_analyzer"]
        primary_ai_analyzer, fallback_ai_analyzer = self._instantiate_ai_analyzers(use_ai_analyzer)

        scan = Scan(
            scan_id=scan_id,
            target=self.target,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(UTC),
            attacks_total=len(self.attacks),
            library_version=library_version,
            analyzers_used=list(analyzers_used),
        )

        try:
            for index, attack in enumerate(self.attacks):
                if on_progress:
                    on_progress(index + 1, len(self.attacks), attack)

                started = time.monotonic()
                response = ""
                finding: Finding | None = None
                analyzers_run_for_attack: list[str] = []

                try:
                    response = await self.send_attack(attack) or ""

                    if response and not response.startswith(("[ERROR]", "[TIMEOUT]")):
                        verdicts: list[AnalyzerVerdict] = []

                        # Pattern analyzer always runs (fast, free)
                        pattern_verdict = pattern_analyzer.analyze(attack, response)
                        verdicts.append(pattern_verdict)
                        analyzers_run_for_attack.append("pattern_analyzer")

                        # AI analyzer: try primary (Claude); on raised exception or
                        # 0.0-confidence "internal failure" verdict, fall back to
                        # the secondary analyzer (OpenAI). At most one AI verdict
                        # is appended, preserving the _combine_verdicts contract.
                        if primary_ai_analyzer is not None:
                            ai_verdict = await self._run_ai_with_fallback(
                                primary_ai_analyzer,
                                fallback_ai_analyzer,
                                attack,
                                response,
                            )
                            if ai_verdict is not None:
                                verdicts.append(ai_verdict)
                                analyzers_run_for_attack.append(ai_verdict.analyzer_name)
                                if ai_verdict.analyzer_name not in analyzers_used:
                                    analyzers_used.append(ai_verdict.analyzer_name)

                        # Combine verdicts
                        success, confidence_score, confidence, needs_review = _combine_verdicts(verdicts)

                        if success:
                            # Build description from analyzer reasoning
                            reasoning_parts = [f"{v.analyzer_name}: {v.reasoning}" for v in verdicts if v.reasoning]
                            description = f"{attack.description}\n\nAnalyzer reasoning:\n" + "\n".join(reasoning_parts)

                            finding = Finding(
                                finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                                attack_id=attack.id,
                                attack_category=attack.category,
                                target_url=self.target.url,
                                severity=attack.severity,
                                confidence=confidence,
                                confidence_score=confidence_score,
                                title=f"{attack.name} - potential vulnerability detected",
                                description=description,
                                evidence={
                                    "attack_prompt": attack.prompt,
                                    "response_snippet": response[:1000],
                                    "owasp_category": attack.owasp_category,
                                    "mitre_atlas": attack.mitre_atlas,
                                    "analyzers_agreed": all(v.success for v in verdicts),
                                },
                                analyzer_verdicts=verdicts,
                                remediation=attack.remediation,
                                needs_manual_review=needs_review,
                            )
                            scan.findings.append(finding)

                    scan.attacks_run += 1
                except Exception as exc:
                    self.errors.append(f"{attack.id}: {exc}")
                    response = f"[ERROR] {exc}"
                    scan.attacks_run += 1

                duration = time.monotonic() - started

                if save_transcripts:
                    truncated = len(response) > MAX_TRANSCRIPT_RESPONSE_CHARS
                    transcript = Transcript(
                        attack_id=attack.id,
                        attack_name=attack.name,
                        owasp_category=attack.owasp_category,
                        severity=attack.severity,
                        prompt=attack.prompt,
                        response=response[:MAX_TRANSCRIPT_RESPONSE_CHARS],
                        response_truncated=truncated,
                        became_finding=finding is not None,
                        finding_id=finding.finding_id if finding else None,
                        duration_seconds=round(duration, 3),
                        analyzers_run=analyzers_run_for_attack,
                    )
                    scan.transcripts.append(transcript)

                rate_delay = 60.0 / max(self.target.rate_limit, 1)
                await asyncio.sleep(rate_delay)

            scan.analyzers_used = list(analyzers_used)
            scan.status = ScanStatus.COMPLETED
        except Exception as exc:
            scan.analyzers_used = list(analyzers_used)
            scan.status = ScanStatus.FAILED
            scan.error = str(exc)
        finally:
            scan.completed_at = datetime.now(UTC)
            await self.cleanup()

        return scan

    def _instantiate_ai_analyzers(
        self, use_ai_analyzer: bool
    ) -> tuple[Any | None, Any | None]:
        """Return ``(primary, fallback)`` AI analyzer instances.

        Claude is the primary AI analyzer; OpenAI is the fallback. If Claude's
        init fails (missing key, missing SDK), OpenAI is promoted to primary so
        the scan still gets AI-quality verdicts when possible. Init failures are
        recorded to ``self.errors`` with the substring ``"AI analyzer disabled"``
        so external monitors can grep for it.
        """
        if not use_ai_analyzer:
            return None, None

        primary: Any | None = None
        try:
            from ..analyzers.claude_analyzer import ClaudeAnalyzer
            primary = ClaudeAnalyzer()
        except (ValueError, ImportError) as exc:
            self.errors.append(f"AI analyzer disabled (claude_analyzer): {exc}")

        fallback: Any | None = None
        try:
            from ..analyzers.openai_analyzer import OpenAIAnalyzer
            fallback = OpenAIAnalyzer()
        except (ValueError, ImportError) as exc:
            self.errors.append(f"AI analyzer disabled (openai_analyzer): {exc}")

        if primary is None and fallback is not None:
            # Claude unavailable — promote OpenAI to primary so the cascade has
            # somewhere to start. There is no further fallback in that case.
            primary, fallback = fallback, None

        return primary, fallback

    async def _run_ai_with_fallback(
        self,
        primary: Any,
        fallback: Any | None,
        attack: Attack,
        response: str,
    ) -> AnalyzerVerdict | None:
        """Run the primary AI analyzer; on failure, try the fallback.

        Treats two outcomes as "primary failed":
          1. ``analyze`` raises an exception, or
          2. ``analyze`` returns a 0.0-confidence verdict (the analyzer's
             internal-error sentinel — auth, network, parse failure).

        Returns the first usable verdict, or ``None`` if both analyzers
        failed. Errors are appended to ``self.errors``.
        """
        primary_verdict = await self._try_analyze(primary, attack, response)
        if primary_verdict is not None and primary_verdict.confidence_score > 0.0:
            return primary_verdict

        if primary_verdict is not None:
            self.errors.append(
                f"{primary.name} returned error verdict for {attack.id}: "
                f"{(primary_verdict.reasoning or '')[:200]}"
            )

        if fallback is None:
            return primary_verdict

        fallback_verdict = await self._try_analyze(fallback, attack, response)
        if fallback_verdict is not None:
            return fallback_verdict
        return primary_verdict

    async def _try_analyze(
        self, analyzer: Any, attack: Attack, response: str
    ) -> AnalyzerVerdict | None:
        """Call ``analyzer.analyze`` and convert raised exceptions into ``None``."""
        try:
            return cast(AnalyzerVerdict, await analyzer.analyze(attack, response))
        except Exception as exc:
            self.errors.append(f"{analyzer.name} failed for {attack.id}: {exc}")
            return None
