# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-06-05

The "multi-provider cascade" release: PromptShield's AI analyzer layer goes from a single Claude integration to a four-tier ensemble with automatic fallback. If Claude is unavailable the orchestrator tries OpenAI GPT-4o-mini, then Google Gemini, then a local Ollama daemon. Deterministic pattern matching remains the floor whenever every AI tier fails.

### Added

- **Pattern + 4-tier AI cascade** (Claude → GPT-4o-mini → Gemini → Ollama → pattern-only floor) **with automatic fallback.** The orchestrator iterates a list of AI analyzers and uses the first one that returns a non-error verdict; pattern matching always runs as a deterministic floor. Adding a fifth provider is a one-line change in `_instantiate_ai_analyzers`.
- **OpenAI analyzer (GPT-4o-mini)** with the same `AnalyzerVerdict` shape as the Claude analyzer. Key precedence `PROMPTSHIELD_ANALYZER_OPENAI_KEY` → `OPENAI_API_KEY`. Uses chat-completions JSON mode for structured output.
- **Google Gemini analyzer** (default model `gemini-2.0-flash-001`, configurable via `PROMPTSHIELD_ANALYZER_GEMINI_MODEL`). Built on the newer `google-genai` SDK. Key precedence `PROMPTSHIELD_ANALYZER_GEMINI_KEY` → `GOOGLE_API_KEY` → `GOOGLE_GENAI_API_KEY`.
- **Ollama analyzer** for fully-local inference (default model `llama3.2:3b`, configurable via `PROMPTSHIELD_ANALYZER_OLLAMA_MODEL`). Host precedence `PROMPTSHIELD_ANALYZER_OLLAMA_HOST` → `OLLAMA_HOST` → `http://localhost:11434`. Connection failures (daemon not running, `httpx.ConnectError`, `ollama.ResponseError`) are caught inside `analyze()` and surfaced as a 0.0-confidence verdict so the cascade falls through cleanly to the pattern floor — they never raise out to the scan.
- **"How PromptShield compares"** section in the README positioning the cascade against Garak, PyRIT, OWASP llm-guard / Rebuff, and the manual-testing baseline.
- **Extension recipe in `CONTRIBUTING.md`** documenting the analyzer interface and the three-step process for adding a fifth provider.
- **44 new tests** across the new analyzers and the cascade orchestration, bringing the suite to **229 tests** with 93% coverage.
- CI uploads `coverage.xml` to Codecov on the 3.13 matrix entry; coverage badge added to the README.

### Changed

- **`engines/base.py` refactored** from the hardcoded `(primary, fallback)` tuple it briefly used during the OpenAI-only iteration to an ordered `list[Analyzer]`. `_instantiate_ai_analyzers` returns the analyzers whose init succeeded; `_run_ai_with_cascade` walks them, treating raised exceptions OR 0.0-confidence error verdicts as "this one failed, try the next." Adding a new analyzer no longer requires any orchestration changes.
- **Test runs are now deterministic across dev machines**: an autouse fixture in `tests/conftest.py` clears every provider's API-key / host / model environment variable before each test, so tests that exercise the cascade can't accidentally pick up a real `OPENAI_API_KEY` or `GOOGLE_API_KEY` from the developer's shell and make a live API call.
- `ollama>=0.3.0` moved from the optional `local-llm` extra into required `[project.dependencies]` (the cascade depends on the fourth provider always being available). The now-empty `local-llm` extra was removed.
- Bumped GitHub Actions versions to clear the Node 20 deprecation warning.
- The CI `lint` job now hard-fails when `ruff check` finds issues (previously advisory).
- Moved internal project blueprint out of the public repo into private continuity notes.

## [0.3.0] - 2026-05-18

The "production-ready CLI" release: hardened scanner, strict typing end-to-end, and a comprehensive test suite for the Click CLI.

### Added

- **Click-based CLI** (`promptshield`) wired up as a `[project.scripts]` entry point in `pyproject.toml`. Subcommands include `scan`, `library list`, `library show`, and `--help` for all of them.
- **Graceful Ctrl+C handling** — `KeyboardInterrupt` mid-scan now stops cleanly with a summary line rather than dumping a traceback.
- **Automatic retry/backoff on the API scanner** via `tenacity` — transient API failures (rate limits, 5xx, timeouts) are retried with exponential backoff; an `_is_retryable` predicate gates which errors qualify.
- **Strict-mode mypy** enabled across the codebase (16 annotation fixes); a dedicated `typecheck` job in CI gates every push.
- **Hardened ruff configuration** with per-file ignores for intentionally long lines (CLI banner art, Claude system prompts, pattern-analyzer reasoning) and a hard-fail ruff job in CI.
- **162-test pytest suite** covering the CLI (25 `CliRunner` tests for argument parsing, banner output, error paths, and Ctrl+C), the API scanner (retry/backoff and `_is_retryable`), the pattern and Claude analyzers, the attack library loader, both reporters (JSON and HTML), and the core models.
- **Coverage uploaded to Codecov** with a per-job artifact; current coverage on `main` is ~93% lines.
- **CI matrix on Python 3.11, 3.12, and 3.13** with three independent jobs: `test`, `lint` (ruff), and `typecheck` (mypy strict).
- **User-Agent derived from package version** so target servers see the exact PromptShield release that contacted them.

### Changed

- Replaced the original ad-hoc CLI scaffold with a Click-driven entry point exposed via `pyproject.toml`'s `[project.scripts]`.
- Tightened the ruff rule set (`E`, `F`, `I`, `N`, `W`, `UP`) and fixed all import-ordering and naming issues it flagged.

### Fixed

- API scanner now derives its User-Agent from `__version__` instead of a hard-coded string, so it stays accurate across releases.

### Security

- API keys are loaded from environment variables / `.env` only — never accepted as CLI flags or written to terminal output.
- API keys and other secrets are automatically redacted from JSON and HTML reports before they're written to disk.
- All outbound API calls use TLS via `httpx`; the scanner refuses plain-HTTP targets unless explicitly overridden.

[Unreleased]: https://github.com/SalCyberAware/PromptShield/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/SalCyberAware/PromptShield/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SalCyberAware/PromptShield/releases/tag/v0.3.0
