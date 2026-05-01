"""JSON report generator."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..models import Scan


class JSONReporter:
    """Generates JSON reports from Scan objects."""

    name = "json"

    def generate(self, scan: Scan, output_path: Path) -> Path:
        """Write the scan results to a JSON file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = scan.model_dump(mode="json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        return output_path

    def to_string(self, scan: Scan) -> str:
        """Return JSON string representation."""
        return json.dumps(scan.model_dump(mode="json"), indent=2, default=str)
