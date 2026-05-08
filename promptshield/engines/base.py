"""Base scanner class - abstract interface all scanners implement.

Supports multiple analyzers (pattern + AI) with confidence-weighted combination.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

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
    async def send_attack(self, attack: Attack) -> Optional[str]:
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
        on_progress=None,
        save_transcripts: bool = True,
        use_ai_analyzer: bool = False,
    ) -> Scan:
        """Execute the full scan and return results."""
        from ..analyzers.pattern import PatternAnalyzer

        pattern_analyzer = PatternAnalyzer()
        analyzers_used = ["pattern_analyzer"]
        ai_analyzer = None

        if use_ai_analyzer:
            try:
                from ..analyzers.claude_analyzer import ClaudeAnalyzer
                ai_analyzer = ClaudeAnalyzer()
                analyzers_used.append("claude_analyzer")
            except (ValueError, ImportError) as exc:
                self.errors.append(f"AI analyzer disabled: {exc}")

        scan = Scan(
            scan_id=scan_id,
            target=self.target,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            attacks_total=len(self.attacks),
            library_version=library_version,
            analyzers_used=analyzers_used,
        )

        try:
            for index, attack in enumerate(self.attacks):
                if on_progress:
                    on_progress(index + 1, len(self.attacks), attack)

                started = time.monotonic()
                response = ""
                finding: Optional[Finding] = None
                analyzers_run_for_attack: list[str] = []

                try:
                    response = await self.send_attack(attack) or ""

                    if response and not response.startswith(("[ERROR]", "[TIMEOUT]")):
                        verdicts: list[AnalyzerVerdict] = []

                        # Pattern analyzer always runs (fast, free)
                        pattern_verdict = pattern_analyzer.analyze(attack, response)
                        verdicts.append(pattern_verdict)
                        analyzers_run_for_attack.append("pattern_analyzer")

                        # AI analyzer runs if enabled
                        if ai_analyzer is not None:
                            try:
                                ai_verdict = await ai_analyzer.analyze(attack, response)
                                verdicts.append(ai_verdict)
                                analyzers_run_for_attack.append("claude_analyzer")
                            except Exception as exc:
                                self.errors.append(f"AI analyzer failed for {attack.id}: {exc}")

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

            scan.status = ScanStatus.COMPLETED
        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.error = str(exc)
        finally:
            scan.completed_at = datetime.now(timezone.utc)
            await self.cleanup()

        return scan
