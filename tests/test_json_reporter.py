"""Tests for the JSON reporter and secret redaction."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptshield.models import (
    AuthType,
    Scan,
    ScanStatus,
    TargetConfig,
    TargetType,
)
from promptshield.reporters.json_reporter import JSONReporter, redact


class TestSecretRedaction:
    """Tests for the redact() function."""

    def test_redacts_anthropic_key_in_string(self) -> None:
        """Should redact Anthropic API keys in any string."""
        text = "My key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABC"
        result = redact(text)
        assert "sk-ant-api03" not in result
        assert "[REDACTED]" in result

    def test_redacts_openai_key_in_string(self) -> None:
        """Should redact OpenAI API keys in any string."""
        text = "OpenAI key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        result = redact(text)
        assert "sk-proj" not in result
        assert "[REDACTED]" in result

    def test_redacts_bearer_token(self) -> None:
        """Should redact bearer tokens."""
        text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123"
        result = redact(text)
        assert "[REDACTED]" in result

    def test_redacts_aws_access_key(self) -> None:
        """Should redact AWS access keys."""
        text = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_redacts_sensitive_dict_keys(self) -> None:
        """Should redact values for keys named auth_value, api_key, etc."""
        data = {"auth_value": "sk-ant-secret", "url": "https://example.com"}
        result = redact(data)
        assert result["auth_value"] == "[REDACTED]"
        assert result["url"] == "https://example.com"  # Non-sensitive preserved

    def test_redacts_nested_secrets(self) -> None:
        """Should redact secrets in nested structures."""
        data = {
            "target": {
                "auth_value": "secret-key",
                "url": "https://example.com",
            }
        }
        result = redact(data)
        assert result["target"]["auth_value"] == "[REDACTED]"

    def test_redacts_secrets_in_lists(self) -> None:
        """Should redact secrets inside lists."""
        data = [{"api_key": "secret-123"}, {"safe": "value"}]
        result = redact(data)
        assert result[0]["api_key"] == "[REDACTED]"
        assert result[1]["safe"] == "value"


class TestJSONReporter:
    """Tests for the JSONReporter class."""

    def _make_sample_scan(self) -> Scan:
        """Build a minimal scan object for testing."""
        return Scan(
            scan_id="SCAN-TEST-001",
            target=TargetConfig(
                url="https://api.anthropic.com/v1/messages",
                target_type=TargetType.API,
                auth_type=AuthType.API_KEY,
                auth_value="sk-ant-test-key-12345",
            ),
            status=ScanStatus.COMPLETED,
            attacks_run=2,
            attacks_total=2,
            library_version="1.0.0",
        )

    def test_writes_file(self, tmp_path: Path) -> None:
        """Should write JSON file to disk."""
        reporter = JSONReporter()
        scan = self._make_sample_scan()
        output_path = tmp_path / "test_scan.json"

        result_path = reporter.generate(scan, output_path)
        assert result_path.exists()

    def test_output_is_valid_json(self, tmp_path: Path) -> None:
        """Output file should be valid JSON."""
        reporter = JSONReporter()
        scan = self._make_sample_scan()
        output_path = tmp_path / "test_scan.json"

        reporter.generate(scan, output_path)
        content = output_path.read_text(encoding="utf-8")
        data = json.loads(content)  # Should not raise

        assert data["scan_id"] == "SCAN-TEST-001"

    def test_auth_value_is_redacted(self, tmp_path: Path) -> None:
        """auth_value field should be redacted in output."""
        reporter = JSONReporter()
        scan = self._make_sample_scan()
        output_path = tmp_path / "test_scan.json"

        reporter.generate(scan, output_path)
        content = output_path.read_text(encoding="utf-8")

        assert "sk-ant-test-key" not in content
        assert "[REDACTED]" in content

    def test_redaction_can_be_disabled(self, tmp_path: Path) -> None:
        """Should preserve secrets when redact_secrets=False."""
        reporter = JSONReporter(redact_secrets=False)
        scan = self._make_sample_scan()
        output_path = tmp_path / "test_scan.json"

        reporter.generate(scan, output_path)
        content = output_path.read_text(encoding="utf-8")

        assert "sk-ant-test-key" in content

    def test_to_string_returns_redacted_json(self) -> None:
        """to_string() should return redacted JSON without writing to disk."""
        reporter = JSONReporter()
        scan = self._make_sample_scan()

        result = reporter.to_string(scan)
        data = json.loads(result)
        assert data["target"]["auth_value"] == "[REDACTED]"

    def test_creates_output_directory(self, tmp_path: Path) -> None:
        """Should create parent directory if it does not exist."""
        reporter = JSONReporter()
        scan = self._make_sample_scan()
        output_path = tmp_path / "nested" / "subdir" / "scan.json"

        reporter.generate(scan, output_path)
        assert output_path.exists()
