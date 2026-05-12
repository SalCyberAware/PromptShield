"""Tests for Pydantic data models."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from promptshield.models import (
    AnalyzerVerdict,
    AttackCategory,
    AuthType,
    Confidence,
    Finding,
    Severity,
    TargetConfig,
    TargetType,
)


class TestEnums:
    """Tests for enum constraints."""

    def test_severity_values(self) -> None:
        """Severity enum should have expected values."""
        assert Severity.LOW.value == "low"
        assert Severity.CRITICAL.value == "critical"

    def test_attack_category_values(self) -> None:
        """AttackCategory should have OWASP-aligned values."""
        assert AttackCategory.LLM01_PROMPT_INJECTION.value == "LLM01"
        assert AttackCategory.LLM10_MODEL_THEFT.value == "LLM10"
        assert AttackCategory.CUSTOM.value == "CUSTOM"


class TestTargetConfig:
    """Tests for TargetConfig model."""

    def test_valid_config(self) -> None:
        """Should accept valid target config."""
        config = TargetConfig(
            url="https://api.example.com",
            target_type=TargetType.API,
            auth_type=AuthType.BEARER,
        )
        assert config.url == "https://api.example.com"

    def test_defaults(self) -> None:
        """Should apply expected defaults."""
        config = TargetConfig(url="https://api.example.com", target_type=TargetType.API)
        assert config.auth_type == AuthType.NONE
        assert config.timeout == 30
        assert config.rate_limit == 10
        assert config.headers == {}


class TestAnalyzerVerdict:
    """Tests for AnalyzerVerdict model."""

    def test_valid_verdict(self) -> None:
        """Should accept valid verdict."""
        verdict = AnalyzerVerdict(
            analyzer_name="test_analyzer",
            success=True,
            confidence_score=0.75,
            reasoning="Test reasoning",
        )
        assert verdict.success is True

    def test_rejects_confidence_below_zero(self) -> None:
        """Confidence score below 0.0 should be rejected."""
        with pytest.raises(ValidationError):
            AnalyzerVerdict(
                analyzer_name="test",
                success=False,
                confidence_score=-0.1,
            )

    def test_rejects_confidence_above_one(self) -> None:
        """Confidence score above 1.0 should be rejected."""
        with pytest.raises(ValidationError):
            AnalyzerVerdict(
                analyzer_name="test",
                success=True,
                confidence_score=1.5,
            )


class TestFinding:
    """Tests for Finding model."""

    def test_valid_finding(self) -> None:
        """Should construct valid finding."""
        finding = Finding(
            finding_id="FND-TEST-001",
            attack_id="PS-TEST-001",
            attack_category=AttackCategory.LLM01_PROMPT_INJECTION,
            target_url="https://example.com",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            confidence_score=0.75,
            title="Test finding",
            description="Test description",
            remediation="Test remediation",
        )
        assert finding.severity == Severity.HIGH

    def test_defaults_for_optional_fields(self) -> None:
        """Optional fields should have sensible defaults."""
        finding = Finding(
            finding_id="FND-001",
            attack_id="PS-001",
            attack_category=AttackCategory.LLM01_PROMPT_INJECTION,
            target_url="https://example.com",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            confidence_score=0.5,
            title="Test",
            description="Test",
            remediation="Test",
        )
        assert finding.needs_manual_review is False
        assert finding.evidence == {}
        assert finding.analyzer_verdicts == []
