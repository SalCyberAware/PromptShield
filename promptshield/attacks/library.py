"""Attack library loader and manager for PromptShield."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from ..models import Attack, AttackCategory, Severity


class AttackLibrary:
    """Loads and manages the PromptShield attack library."""

    def __init__(self, library_path: Optional[Path] = None) -> None:
        if library_path is None:
            library_path = Path(__file__).parent / "data" / "attacks_v1.yaml"
        self.library_path = library_path
        self.attacks: list[Attack] = []
        self._load()

    def _load(self) -> None:
        """Load attacks from YAML file."""
        if not self.library_path.exists():
            self.attacks = []
            return

        with open(self.library_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        raw_attacks = data.get("attacks", [])
        self.attacks = []
        for raw in raw_attacks:
            try:
                attack = Attack(
                    id=raw["id"],
                    category=AttackCategory(raw["category"]),
                    owasp_category=raw["owasp_category"],
                    mitre_atlas=raw.get("mitre_atlas"),
                    name=raw["name"],
                    description=raw["description"],
                    severity=Severity(raw["severity"]),
                    prompt=raw["prompt"],
                    expected_indicators=raw.get("expected_indicators", []),
                    false_positive_patterns=raw.get("false_positive_patterns", []),
                    remediation=raw["remediation"],
                    references=raw.get("references", []),
                    tags=raw.get("tags", []),
                )
                self.attacks.append(attack)
            except (KeyError, ValueError) as exc:
                print(f"Warning: skipping malformed attack {raw.get('id', 'unknown')}: {exc}")

    def all(self) -> list[Attack]:
        """Return all attacks."""
        return self.attacks

    def by_category(self, category: AttackCategory) -> list[Attack]:
        """Return attacks filtered by category."""
        return [a for a in self.attacks if a.category == category]

    def by_owasp(self, owasp_code: str) -> list[Attack]:
        """Return attacks filtered by OWASP category code (e.g., 'LLM01')."""
        return [a for a in self.attacks if a.owasp_category == owasp_code]

    def by_severity(self, severity: Severity) -> list[Attack]:
        """Return attacks filtered by severity level."""
        return [a for a in self.attacks if a.severity == severity]

    def by_tag(self, tag: str) -> list[Attack]:
        """Return attacks that have a specific tag."""
        return [a for a in self.attacks if tag in a.tags]

    def get(self, attack_id: str) -> Optional[Attack]:
        """Get a single attack by ID."""
        for attack in self.attacks:
            if attack.id == attack_id:
                return attack
        return None

    def stats(self) -> dict[str, int]:
        """Return statistics about the library."""
        stats: dict[str, int] = {"total": len(self.attacks)}
        for category in AttackCategory:
            count = len(self.by_category(category))
            if count > 0:
                stats[category.value] = count
        for severity in Severity:
            count = len(self.by_severity(severity))
            if count > 0:
                stats[f"severity_{severity.value}"] = count
        return stats

    def __len__(self) -> int:
        return len(self.attacks)

    def __iter__(self):
        return iter(self.attacks)
