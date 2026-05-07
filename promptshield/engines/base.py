"""Base scanner class - abstract interface all scanners implement."""
from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

from ..models import (
    Attack,
    Finding,
    Scan,
    ScanStatus,
    TargetConfig,
    Transcript,
)

# Cap stored response size to keep scan files reasonable
MAX_TRANSCRIPT_RESPONSE_CHARS = 5000


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
    ) -> Scan:
        """Execute the full scan and return results."""
        from ..analyzers.pattern import PatternAnalyzer

        scan = Scan(
            scan_id=scan_id,
            target=self.target,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            attacks_total=len(self.attacks),
            library_version=library_version,
        )

        analyzer = PatternAnalyzer()

        try:
            for index, attack in enumerate(self.attacks):
                if on_progress:
                    on_progress(index + 1, len(self.attacks), attack)

                started = time.monotonic()
                response = ""
                finding: Optional[Finding] = None

                try:
                    response = await self.send_attack(attack) or ""

                    if response and not response.startswith(("[ERROR]", "[TIMEOUT]")):
                        finding = analyzer.analyze(
                            attack=attack,
                            response=response,
                            target_url=self.target.url,
                        )
                        if finding:
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
