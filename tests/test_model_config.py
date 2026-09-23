"""Tests for the pinned model configuration (issue #2).

A security tool's verdicts must be reproducible. These tests pin down the two
properties that matter: the shipped defaults are exact versions rather than
floating aliases, and a deployment can still override them.

No network, no API keys, no spend — every assertion is against config values.
"""
from __future__ import annotations

import pytest

from promptshield import model_config
from promptshield.analyzers.gemini_analyzer import GeminiAnalyzer
from promptshield.analyzers.ollama_analyzer import OllamaAnalyzer
from promptshield.engines.system_prompt_scanner import default_target_model


class TestPinsAreExactVersions:
    """The shipped defaults must not be aliases a provider can repoint."""

    def test_target_is_the_dated_openai_snapshot(self) -> None:
        assert model_config.TARGET_MODEL == "gpt-4o-mini-2024-07-18"
        assert model_config.TARGET_MODEL != "gpt-4o-mini"

    def test_openai_judge_is_the_dated_snapshot(self) -> None:
        assert model_config.OPENAI_JUDGE_MODEL == "gpt-4o-mini-2024-07-18"
        assert model_config.OPENAI_JUDGE_MODEL != "gpt-4o-mini"

    def test_gemini_judge_names_a_model_google_still_serves(self) -> None:
        """The `-001` pin was retired out from under us.

        `gemini-2.0-flash-001` now returns a hard 404, which surfaced the moment
        the eval harness started using Gemini as a fallback judge: every
        fallback call failed and the case was recorded unjudged. This
        generation publishes no dated form -- `gemini-3.6-flash-001` is a 404
        too -- so the bare id is what Google serves and what is pinned.
        """
        assert model_config.GEMINI_JUDGE_MODEL == "gemini-3.6-flash"
        assert "2.0" not in model_config.GEMINI_JUDGE_MODEL

    @pytest.mark.parametrize(
        "model",
        [model_config.ANTHROPIC_JUDGE_MODEL, model_config.WEB_ANTHROPIC_JUDGE_MODEL],
    )
    def test_anthropic_judges_name_one_model_version(self, model: str) -> None:
        """Anthropic ids of this generation are already version-complete.

        `claude-sonnet-4-6` never silently becomes Sonnet 5, and appending a date
        suffix would be an invalid id — so these are pinned as published.
        """
        assert model.startswith("claude-")
        assert model in {"claude-haiku-4-5-20251001", "claude-sonnet-4-6"}

    def test_every_pin_is_listed_for_documentation(self) -> None:
        """PINNED_MODELS is what docs and diagnostics read; keep it complete."""
        assert set(model_config.PINNED_MODELS) == {
            "target",
            "judge_anthropic",
            "judge_anthropic_web",
            "judge_openai",
            "judge_gemini",
            "judge_ollama",
            "scan_target_anthropic",
            "scan_target_openai",
        }
        assert all(v for v in model_config.PINNED_MODELS.values())


class TestResolve:
    """Config, not code: a deployment overrides a pin by environment variable."""

    def test_returns_the_pin_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PROMPTSHIELD_TEST_MODEL", raising=False)
        assert model_config.resolve("pinned-v1", "PROMPTSHIELD_TEST_MODEL") == "pinned-v1"

    def test_env_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PROMPTSHIELD_TEST_MODEL", "override-v2")
        assert model_config.resolve("pinned-v1", "PROMPTSHIELD_TEST_MODEL") == "override-v2"

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_blank_override_falls_back_to_the_pin(
        self, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        """A blank var in a deploy config must not yield an empty model id."""
        monkeypatch.setenv("PROMPTSHIELD_TEST_MODEL", blank)
        assert model_config.resolve("pinned-v1", "PROMPTSHIELD_TEST_MODEL") == "pinned-v1"

    def test_override_is_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PROMPTSHIELD_TEST_MODEL", "  gpt-4o-2024-11-20  ")
        assert (
            model_config.resolve("pinned-v1", "PROMPTSHIELD_TEST_MODEL")
            == "gpt-4o-2024-11-20"
        )


class TestCallersUseTheConfig:
    """Each call site must read the pin, so there is one place to change it."""

    def test_target_default_comes_from_the_pin(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(model_config.TARGET_MODEL_ENV, raising=False)
        assert default_target_model() == model_config.TARGET_MODEL

    def test_target_honours_its_env_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(model_config.TARGET_MODEL_ENV, "gpt-4o-2024-11-20")
        assert default_target_model() == "gpt-4o-2024-11-20"

    def test_gemini_analyzer_defaults_to_the_pin(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(model_config.GEMINI_JUDGE_MODEL_ENV, raising=False)
        monkeypatch.setenv("PROMPTSHIELD_ANALYZER_GEMINI_KEY", "test-key")
        assert GeminiAnalyzer().model == model_config.GEMINI_JUDGE_MODEL

    def test_ollama_analyzer_defaults_to_the_pin(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(model_config.OLLAMA_JUDGE_MODEL_ENV, raising=False)
        assert OllamaAnalyzer().model == model_config.OLLAMA_JUDGE_MODEL

    def test_no_model_id_literals_left_outside_the_config(self) -> None:
        """The pins live in exactly one module; nothing else hardcodes an id.

        Guards the property issue #2 actually asked for — 'in config not code'.
        A new analyzer that inlines a model string fails here.
        """
        import re
        from pathlib import Path

        package = Path(model_config.__file__).parent
        # Provider-shaped model ids: gpt-*, claude-*, gemini-*, llama*:tag
        pattern = re.compile(r"[\"'](gpt-[\w.\-]+|claude-[\w.\-]+|gemini-[\w.\-]+|llama[\w.]*:[\w.]+)[\"']")

        offenders: list[str] = []
        for path in package.rglob("*.py"):
            if path.name == "model_config.py":
                continue
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                # Prose in docstrings and comments may name a model freely.
                if stripped.startswith("#"):
                    continue
                if pattern.search(line):
                    offenders.append(f"{path.relative_to(package)}:{number}: {stripped}")

        assert not offenders, "model ids must live in model_config.py:\n" + "\n".join(
            offenders
        )
