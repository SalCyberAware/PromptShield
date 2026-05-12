"""JSON report generator with automatic secret redaction."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from ..models import Scan

# Patterns that look like API keys, tokens, or credentials
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),       # Anthropic
    re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"),            # OpenAI
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),                  # AWS access key
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),            # Google API key
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),               # GitHub token
    re.compile(r"xoxb-[a-zA-Z0-9\-]{20,}"),           # Slack bot token
]

# JSON field names whose values should always be redacted
SENSITIVE_FIELD_NAMES = {
    "auth_value",
    "api_key",
    "apikey",
    "token",
    "password",
    "secret",
    "x-api-key",
    "authorization",
}


def _redact_string(value: str) -> str:
    """Redact secrets from a string."""
    if not isinstance(value, str):
        return value
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _redact_value(key: str, value: Any) -> Any:
    """Redact a value if its key indicates it's sensitive, otherwise scrub strings."""
    key_lower = key.lower() if isinstance(key, str) else ""
    if key_lower in SENSITIVE_FIELD_NAMES:
        if value is None or value == "":
            return value
        return "[REDACTED]"
    if isinstance(value, str):
        return _redact_string(value)
    return value


def redact(data: Any) -> Any:
    """Recursively redact sensitive data from a dict/list/string."""
    if isinstance(data, dict):
        return {k: redact(_redact_value(k, v)) for k, v in data.items()}
    if isinstance(data, list):
        return [redact(item) for item in data]
    if isinstance(data, str):
        return _redact_string(data)
    return data


class JSONReporter:
    """Generates JSON reports from Scan objects, with secret redaction by default."""

    name = "json"

    def __init__(self, redact_secrets: bool = True) -> None:
        self.redact_secrets = redact_secrets

    def _prepare(self, scan: Scan) -> dict:
        data = scan.model_dump(mode="json")
        if self.redact_secrets:
            data = redact(copy.deepcopy(data))
        return data

    def generate(self, scan: Scan, output_path: Path) -> Path:
        """Write the scan results to a JSON file with secrets redacted."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = self._prepare(scan)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return output_path

    def to_string(self, scan: Scan) -> str:
        """Return JSON string representation with secrets redacted."""
        return json.dumps(self._prepare(scan), indent=2, default=str)
