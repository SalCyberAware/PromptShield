# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI uploads `coverage.xml` to Codecov on the 3.13 matrix entry; coverage badge added to the README.

### Changed

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

[Unreleased]: https://github.com/SalCyberAware/PromptShield/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/SalCyberAware/PromptShield/releases/tag/v0.3.0
