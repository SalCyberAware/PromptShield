"""Tests for the attack library loader and filtering."""
from __future__ import annotations

from pathlib import Path

import pytest

from promptshield.attacks.library import AttackLibrary
from promptshield.models import AttackCategory, Severity


@pytest.fixture
def real_library() -> AttackLibrary:
    """Load the real bundled attack library."""
    return AttackLibrary()


class TestAttackLibraryLoading:
    """Tests for AttackLibrary file loading."""

    def test_loads_default_library(self, real_library: AttackLibrary) -> None:
        """Library should load the default bundled YAML file."""
        assert len(real_library) > 0

    def test_loads_at_least_50_attacks(self, real_library: AttackLibrary) -> None:
        """Library should have at least 50 attacks per Phase 1 milestone."""
        assert len(real_library) >= 50

    def test_handles_missing_file(self) -> None:
        """Library should handle missing file gracefully."""
        lib = AttackLibrary(library_path=Path("/nonexistent/path/library.yaml"))
        assert len(lib) == 0

    def test_all_attacks_have_unique_ids(self, real_library: AttackLibrary) -> None:
        """All attack IDs should be unique."""
        ids = [a.id for a in real_library.all()]
        assert len(ids) == len(set(ids)), "Duplicate IDs found in attack library"


class TestAttackLibraryFiltering:
    """Tests for attack library filtering methods."""

    def test_filter_by_owasp_category(self, real_library: AttackLibrary) -> None:
        """Filter attacks by OWASP category code."""
        llm01_attacks = real_library.by_owasp("LLM01")
        assert len(llm01_attacks) > 0
        assert all(a.owasp_category == "LLM01" for a in llm01_attacks)

    def test_filter_by_category_enum(self, real_library: AttackLibrary) -> None:
        """Filter attacks by AttackCategory enum."""
        attacks = real_library.by_category(AttackCategory.LLM06_SENSITIVE_INFO_DISCLOSURE)
        assert all(a.category == AttackCategory.LLM06_SENSITIVE_INFO_DISCLOSURE for a in attacks)

    def test_filter_by_severity(self, real_library: AttackLibrary) -> None:
        """Filter attacks by severity level."""
        critical = real_library.by_severity(Severity.CRITICAL)
        assert all(a.severity == Severity.CRITICAL for a in critical)

    def test_filter_by_tag(self, real_library: AttackLibrary) -> None:
        """Filter attacks by tag."""
        injection_attacks = real_library.by_tag("prompt_injection")
        assert all("prompt_injection" in a.tags for a in injection_attacks)


class TestAttackLibraryLookup:
    """Tests for direct attack lookup by ID."""

    def test_get_existing_attack(self, real_library: AttackLibrary) -> None:
        """Should retrieve an attack by its ID."""
        attack = real_library.get("PS-LLM01-001")
        assert attack is not None
        assert attack.id == "PS-LLM01-001"

    def test_get_nonexistent_attack(self, real_library: AttackLibrary) -> None:
        """Should return None for unknown IDs."""
        attack = real_library.get("PS-FAKE-999")
        assert attack is None


class TestAttackLibraryStats:
    """Tests for library statistics."""

    def test_stats_total(self, real_library: AttackLibrary) -> None:
        """Stats should include total count."""
        stats = real_library.stats()
        assert "total" in stats
        assert stats["total"] == len(real_library)

    def test_stats_includes_categories(self, real_library: AttackLibrary) -> None:
        """Stats should include per-category counts."""
        stats = real_library.stats()
        # At least LLM01 should be present
        assert "LLM01" in stats

    def test_stats_includes_severities(self, real_library: AttackLibrary) -> None:
        """Stats should include per-severity counts."""
        stats = real_library.stats()
        # At least one severity should be present
        severity_keys = [k for k in stats if k.startswith("severity_")]
        assert len(severity_keys) > 0


class TestAttackLibraryIteration:
    """Tests for iteration and length operations."""

    def test_len(self, real_library: AttackLibrary) -> None:
        """__len__ should return attack count."""
        assert len(real_library) == len(real_library.all())

    def test_iter(self, real_library: AttackLibrary) -> None:
        """__iter__ should iterate over all attacks."""
        count = sum(1 for _ in real_library)
        assert count == len(real_library)
