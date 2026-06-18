"""Unit tests for the web-demo scan orchestration service (backend/scan.py).

No real API calls: the AsyncOpenAI target and the AI analyzers are mocked, and
the backend ``conftest.py`` autouse fixture clears all provider env vars so a
developer's real keys can't leak into the assertions. Async paths are driven via
``asyncio.run`` so no pytest-asyncio dependency is needed.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
import scan
from scan import (
    DEFAULT_ANALYZER_ANTHROPIC_MODEL,
    WEB_DEMO_ATTACK_IDS,
    analyzer_anthropic_model,
    build_web_analyzers,
    load_web_demo_attacks,
    run_web_scan,
)

from promptshield.models import ScanStatus, TargetType

# ── Decision 1: the trimmed attack set ──────────────────────────────────────────


class TestLoadWebDemoAttacks:
    def test_loads_exactly_the_thirteen_not_all_fifty(self) -> None:
        """Filters the library down to the 13 allowlisted IDs, in order."""
        attacks = load_web_demo_attacks()

        assert len(attacks) == 13
        assert len(attacks) != 50
        assert [a.id for a in attacks] == list(WEB_DEMO_ATTACK_IDS)

    def test_set_spans_the_six_expected_owasp_categories(self) -> None:
        """Decision 1 coverage: LLM01, LLM02, LLM06, LLM08, LLM09, LLM10."""
        categories = {a.owasp_category for a in load_web_demo_attacks()}

        assert categories == {"LLM01", "LLM02", "LLM06", "LLM08", "LLM09", "LLM10"}

    def test_missing_or_renamed_id_raises_clear_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A drifted allowlist fails loudly, naming the offending ID."""
        monkeypatch.setattr(
            scan, "WEB_DEMO_ATTACK_IDS", (*WEB_DEMO_ATTACK_IDS[:2], "PS-BOGUS-999")
        )
        with pytest.raises(ValueError, match="PS-BOGUS-999"):
            load_web_demo_attacks()


# ── Decision 2: analyzer configuration ──────────────────────────────────────────


class TestAnalyzerConfig:
    def test_anthropic_model_defaults_to_sonnet(self) -> None:
        assert analyzer_anthropic_model() == DEFAULT_ANALYZER_ANTHROPIC_MODEL == "claude-sonnet-4-6"

    def test_anthropic_model_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_ANTHROPIC_MODEL", "claude-sonnet-4-7")
        assert analyzer_anthropic_model() == "claude-sonnet-4-7"

    def test_cascade_is_trimmed_two_tier_not_four_tier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """[Claude Sonnet, Gemini Flash] only — never the engine's 4-tier default."""
        mock_claude_cls = MagicMock()
        mock_claude_cls.return_value.name = "claude_analyzer"
        mock_gemini_cls = MagicMock()
        mock_gemini_cls.return_value.name = "gemini_analyzer"
        monkeypatch.setattr(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer", mock_claude_cls
        )
        monkeypatch.setattr(
            "promptshield.analyzers.gemini_analyzer.GeminiAnalyzer", mock_gemini_cls
        )

        analyzers = build_web_analyzers()

        # Trimmed cascade in priority order; no openai/ollama tiers.
        assert [a.name for a in analyzers] == ["claude_analyzer", "gemini_analyzer"]
        assert len(analyzers) == 2
        # Claude pinned to the Sonnet tier; Gemini left at its Flash default.
        mock_claude_cls.assert_called_once_with(model="claude-sonnet-4-6")
        mock_gemini_cls.assert_called_once_with()

    def test_cascade_env_override_flows_into_claude(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_claude_cls = MagicMock()
        mock_gemini_cls = MagicMock()
        monkeypatch.setattr(
            "promptshield.analyzers.claude_analyzer.ClaudeAnalyzer", mock_claude_cls
        )
        monkeypatch.setattr(
            "promptshield.analyzers.gemini_analyzer.GeminiAnalyzer", mock_gemini_cls
        )
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_ANTHROPIC_MODEL", "claude-sonnet-4-7")

        build_web_analyzers()

        mock_claude_cls.assert_called_once_with(model="claude-sonnet-4-7")

    def test_unconfigured_providers_are_skipped(self) -> None:
        """With no keys (conftest clears them) both tiers are skipped -> pattern floor only."""
        # Real analyzer classes raise ValueError before touching their SDKs.
        assert build_web_analyzers() == []


# ── run_web_scan orchestration ──────────────────────────────────────────────────


class TestRunWebScan:
    def test_builds_scanner_with_configured_target_and_forwards_cascade(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SystemPromptScanner gets the system prompt + env-resolved target; the
        trimmed cascade is forwarded to run_scan; the Scan is returned."""
        monkeypatch.setenv("PROMPTSHIELD_TARGET_MODEL", "gpt-4o")

        sentinel_scan = object()
        instance = MagicMock()
        instance.run_scan = AsyncMock(return_value=sentinel_scan)
        scanner_cls = MagicMock(return_value=instance)
        monkeypatch.setattr(scan, "SystemPromptScanner", scanner_cls)
        monkeypatch.setattr(scan, "build_web_analyzers", lambda: ["CASCADE_SENTINEL"])

        result = asyncio.run(run_web_scan("You are a helpful assistant."))

        assert result is sentinel_scan

        scanner_cls.assert_called_once()
        args, kwargs = scanner_cls.call_args
        target = args[0]
        assert target.target_type == TargetType.SYSTEM_PROMPT
        assert target.url == "internal://gpt-4o"  # env override respected
        assert len(args[1]) == 13  # the 13-attack set
        assert kwargs["system_prompt"] == "You are a helpful assistant."
        assert kwargs["model"] == "gpt-4o"

        instance.run_scan.assert_awaited_once()
        run_kwargs = instance.run_scan.await_args.kwargs
        assert run_kwargs["analyzers"] == ["CASCADE_SENTINEL"]
        assert run_kwargs["on_progress"] is None
        assert run_kwargs["scan_id"].startswith("web-")

    def test_on_progress_invoked_once_per_attack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end through the real run_scan (target call + sleep mocked):
        on_progress fires once per attack with (current, total, attack)."""
        # Key so SystemPromptScanner constructs; no anthropic/gemini keys, so the
        # cascade degrades to the pattern floor (no AI calls).
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
        monkeypatch.setattr(
            "promptshield.engines.system_prompt_scanner.SystemPromptScanner.send_attack",
            AsyncMock(return_value="I cannot help with that request."),
        )
        # Kill the inter-attack pacing sleep so the test is fast.
        monkeypatch.setattr("promptshield.engines.base.asyncio.sleep", AsyncMock())

        calls: list[tuple[int, int, str]] = []

        def on_progress(current: int, total: int, attack: object) -> None:
            calls.append((current, total, attack.id))  # type: ignore[attr-defined]

        asyncio.run(run_web_scan("You are a helpful assistant.", on_progress))

        assert [c[0] for c in calls] == list(range(1, 14))
        assert all(c[1] == 13 for c in calls)
        assert [c[2] for c in calls] == list(WEB_DEMO_ATTACK_IDS)

    def test_returns_completed_scan_shape(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The aggregated result is a completed Scan over all 13 attacks."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
        monkeypatch.setattr(
            "promptshield.engines.system_prompt_scanner.SystemPromptScanner.send_attack",
            AsyncMock(return_value="I cannot help with that request."),
        )
        monkeypatch.setattr("promptshield.engines.base.asyncio.sleep", AsyncMock())

        scan_result = asyncio.run(run_web_scan("You are a helpful assistant."))

        assert scan_result.status == ScanStatus.COMPLETED
        assert scan_result.attacks_total == 13
        assert scan_result.attacks_run == 13
        assert scan_result.scan_id.startswith("web-")
        assert scan_result.target.target_type == TargetType.SYSTEM_PROMPT
        assert "pattern_analyzer" in scan_result.analyzers_used
