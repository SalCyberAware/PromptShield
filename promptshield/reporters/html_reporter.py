"""HTML report generator for PromptShield scans."""
from __future__ import annotations

import copy
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from ..models import Scan
from .json_reporter import redact
from typing import Any

_TEMPLATE_NAME = "scan_report.html.j2"

# Severity sort order (critical first, info last)
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(severity_value: str) -> int:
    return _SEVERITY_RANK.get(severity_value, 99)


class HTMLReporter:
    """Generates a self-contained HTML report from a Scan.

    The output is a single HTML file with inline CSS, suitable for sharing
    by email or attaching to a ticket. Secrets are redacted by default
    using the same logic as JSONReporter.
    """

    name = "html"

    def __init__(self, redact_secrets: bool = True) -> None:
        self.redact_secrets = redact_secrets
        self._env = Environment(
            loader=PackageLoader("promptshield.reporters", "templates"),
            autoescape=select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def _prepare(self, scan: Scan) -> dict[str, Any]:
        data = scan.model_dump(mode="json")
        if self.redact_secrets:
            data = redact(copy.deepcopy(data))

        # Sort findings by severity (critical first), then by confidence desc
        findings = data.get("findings", [])
        findings_sorted = sorted(
            findings,
            key=lambda f: (
                _severity_rank(f.get("severity", "info")),
                -float(f.get("confidence_score") or 0.0),
            ),
        )
        data["findings"] = findings_sorted

        # Pre-compute summary counts for the template
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_sorted:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        data["_by_severity"] = by_severity

        by_category: dict[str, int] = {}
        for f in findings_sorted:
            evidence = f.get("evidence") or {}
            cat = evidence.get("owasp_category") or f.get("attack_category", "?")
            by_category[cat] = by_category.get(cat, 0) + 1
        data["_by_category"] = dict(sorted(by_category.items()))

        # Pre-compute scan duration in seconds (None if not finished)
        duration = None
        if scan.started_at and scan.completed_at:
            duration = round(
                (scan.completed_at - scan.started_at).total_seconds(), 1
            )
        data["_duration_seconds"] = duration

        return data

    def generate(self, scan: Scan, output_path: Path) -> Path:
        """Write the scan results to a self-contained HTML file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        template = self._env.get_template(_TEMPLATE_NAME)
        html = template.render(scan=self._prepare(scan))
        output_path.write_text(html, encoding="utf-8")
        return output_path

    def to_string(self, scan: Scan) -> str:
        """Return the HTML report as a string."""
        template = self._env.get_template(_TEMPLATE_NAME)
        return template.render(scan=self._prepare(scan))
