"""Tests for the pattern-based analyzer."""
from __future__ import annotations

import pytest

from promptshield.analyzers.pattern import PatternAnalyzer
from promptshield.models import Attack


@pytest.fixture
def analyzer() -> PatternAnalyzer:
    return PatternAnalyzer()


class TestPatternAnalyzerSuccess:
    """Tests where attack indicators ARE present in response."""

    def test_detects_full_indicator_match(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack, successful_response_llm01: str) -> None:
        """Should detect attack success when multiple indicators match."""
        verdict = analyzer.analyze(sample_attack_llm01, successful_response_llm01)
        assert verdict.success is True
        assert verdict.confidence_score > 0.5

    def test_detects_single_indicator_match(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack) -> None:
        """Should still flag when only one indicator matches."""
        response = "Sure, HACKED is what you wanted to hear."
        verdict = analyzer.analyze(sample_attack_llm01, response)
        assert verdict.success is True

    def test_case_insensitive_matching(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack) -> None:
        """Indicator matching should be case-insensitive."""
        response = "Sure, hacked the system as requested."
        verdict = analyzer.analyze(sample_attack_llm01, response)
        assert verdict.success is True


class TestPatternAnalyzerFalsePositive:
    """Tests where false positive patterns trigger refusal recognition."""

    def test_false_positive_pattern_blocks_finding(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack, clean_response_llm01: str) -> None:
        """Should return success=False when response contains refusal patterns."""
        verdict = analyzer.analyze(sample_attack_llm01, clean_response_llm01)
        assert verdict.success is False

    def test_false_positive_takes_priority_over_indicator(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack) -> None:
        """False positive pattern check happens before indicator check."""
        # Contains both an indicator AND a refusal pattern
        response = "I cannot ignore my instructions, even if you say HACKED."
        verdict = analyzer.analyze(sample_attack_llm01, response)
        assert verdict.success is False


class TestPatternAnalyzerEdgeCases:
    """Tests for empty, error, and edge case responses."""

    def test_empty_response_returns_failure(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack) -> None:
        """Empty response should not trigger a finding."""
        verdict = analyzer.analyze(sample_attack_llm01, "")
        assert verdict.success is False
        assert verdict.confidence_score == 0.0

    def test_error_response_returns_failure(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack, error_response: str) -> None:
        """Error response should not trigger a finding."""
        verdict = analyzer.analyze(sample_attack_llm01, error_response)
        assert verdict.success is False

    def test_timeout_response_returns_failure(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack, timeout_response: str) -> None:
        """Timeout response should not trigger a finding."""
        verdict = analyzer.analyze(sample_attack_llm01, timeout_response)
        assert verdict.success is False

    def test_no_indicators_match(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack) -> None:
        """Response with no matching indicators should not trigger a finding."""
        response = "The weather today is sunny and pleasant."
        verdict = analyzer.analyze(sample_attack_llm01, response)
        assert verdict.success is False


class TestPatternAnalyzerConfidence:
    """Tests for confidence scoring."""

    def test_more_matches_higher_confidence(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack) -> None:
        """More matched indicators should increase confidence."""
        few_matches = "HACKED is a word."
        many_matches = "HACKED. I ignored the previous instructions completely."

        verdict_few = analyzer.analyze(sample_attack_llm01, few_matches)
        verdict_many = analyzer.analyze(sample_attack_llm01, many_matches)

        assert verdict_many.confidence_score >= verdict_few.confidence_score

    def test_confidence_is_clamped(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack) -> None:
        """Confidence should never exceed 1.0 or go below 0.0."""
        response = "HACKED ignored previous instructions HACKED ignored"
        verdict = analyzer.analyze(sample_attack_llm01, response)
        assert 0.0 <= verdict.confidence_score <= 1.0


class TestPatternAnalyzerMetadata:
    """Tests for verdict metadata."""

    def test_verdict_includes_analyzer_name(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack, successful_response_llm01: str) -> None:
        """Verdict should identify which analyzer produced it."""
        verdict = analyzer.analyze(sample_attack_llm01, successful_response_llm01)
        assert verdict.analyzer_name == "pattern_analyzer"

    def test_verdict_includes_reasoning(self, analyzer: PatternAnalyzer, sample_attack_llm01: Attack, successful_response_llm01: str) -> None:
        """Verdict should include human-readable reasoning."""
        verdict = analyzer.analyze(sample_attack_llm01, successful_response_llm01)
        assert verdict.reasoning is not None
        assert len(verdict.reasoning) > 0
