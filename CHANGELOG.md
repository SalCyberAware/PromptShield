# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-09-01

The "web product" release: PromptShield stops being a CLI you install and becomes a URL you visit. Paste a system prompt at [the live demo](https://prompt-shield-mocha.vercel.app), and a server-side target model runs 13 attacks against it while the results stream in. The engine underneath is unchanged — the web layer is a thin FastAPI wrapper that imports `promptshield` as a library.

The headline change is the honesty model. A scan no longer reports a binary pass/fail per attack. Every attack carries an explicit status, and the two statuses that mean "we could not tell" are never laundered into "held".

### Added

- **`SystemPromptScanner` target adapter** (`promptshield/engines/system_prompt_scanner.py`) — the one detection-core addition behind the web product. Where `APIScanner` fires attacks at a third-party endpoint the user owns, this scanner attacks a *pasted system prompt* by calling a server-side model on our keys, sending `[system: <pasted prompt>, user: <attack.prompt>]` per attack. It is a drop-in `BaseScanner` subclass using the identical `[ERROR]`/`[TIMEOUT]` string-prefix convention, so `run_scan`'s analysis gating works unchanged. Targets have no real URL, so callers pass an `internal://<model>` sentinel. Default target `gpt-4o-mini`, overridable via `PROMPTSHIELD_TARGET_MODEL`.
- **FastAPI backend** (`backend/`) exposing `GET /api/health` and `POST /api/scan/stream`. Health reports the engine version plus a `providers` map of which server-side providers are configured — **booleans only, never key values**.
- **SSE streaming scan endpoint.** `POST /api/scan/stream` emits `start` → `progress*` → (`done` | `error`) frames. `run_web_scan`'s synchronous `on_progress` callback is bridged to the stream through an `asyncio.Queue` while the scan runs as a background task; the task always enqueues a terminal event followed by a `None` sentinel, so the stream closes cleanly even when the scan raises rather than hanging the client. Sent with `Cache-Control: no-cache` and `X-Accel-Buffering: no` so proxies don't buffer the stream.
- **Explicit per-attack status model** replacing the binary vulnerable/not flag. Every attack resolves to one of `vulnerable`, `held`, `needs_review`, `error`, or `not_ai_judged`. **The core honesty rule: `error` and `not_ai_judged` are never counted or displayed as `held`.** An attack whose target call failed, or whose reply no AI judge managed to score, is reported as untested — not as a defense that worked. Only `vulnerable` and `needs_review` feed the severity and OWASP breakdowns; the `done` headline counts only AI-confirmed got-throughs as failed and only AI-confirmed defenses as passed, leaving the other three statuses deliberately in neither bucket.
- **Cross-provider judging for the web demo.** A trimmed 2-tier cascade — Claude Sonnet (`claude-sonnet-4-6`, overridable via `PROMPTSHIELD_ANALYZER_ANTHROPIC_MODEL`) → Gemini Flash — on top of the always-on pattern floor. Deliberately **not** the engine's default 4-tier cascade: OpenAI is excluded because it is the target here, so judging with it would carry same-family bias. A tier whose key or SDK is missing is skipped rather than failing the scan, degrading to the pattern floor.
- **Ensemble judging behind a flag, default off.** Set `PROMPTSHIELD_WEB_ENSEMBLE` to `1`/`true`/`yes`/`on` and both judges score every attack, with verdicts aggregated: two judges agreeing gives that decision with `agreement: "agree"` and the higher of the two confidence scores; two judges disagreeing forces `needs_review` with `agreement: "disagree"` and a null confidence. A single judge outage (a Gemini 429, say) drops that verdict rather than breaking the attack. The target is still called exactly once — only judge calls double.
- **Curated, bounded result payload** (`serialize_scan_result`). Each attack carries its status, provenance (`judged_by`), confidence score and band, an ensemble-ready `verdicts` list, and an `aggregate`. The only target output included is a `response_excerpt` capped at 600 characters, populated only for statuses where the reply is evidence the UI needs. API keys are never part of any field.
- **React + Vite frontend** (`frontend/`) with a dark design-token system: a scan input with "Try a leaky prompt" / "Try a hardened prompt" examples, live per-attack progress driven by the SSE stream, and a status-aware results view rendering findings in importance order (`vulnerable` → `needs_review` → `not_ai_judged` → `error` → `held`, with held collapsed and quiet). The SSE client (`lib/scanStream.js`) is deliberately React-free — `EventSource` is GET-only, so it reads the response body via a `ReadableStream` reader with a buffer that survives chunk boundaries.
- **OWASP coverage panel that reports what it cannot test.** The demo tests 6 of the 10 OWASP LLM categories; supply chain, training-data poisoning, and plugin design need a live application, so they are shown as not applicable and **never counted as passed**.
- **Abuse controls gating the scan endpoint** (`backend/limits.py`), all applied before any target or judge call so a rejected request spends nothing. Checks run cheapest-first and consume a slot only if all pass: an 8,000-character system-prompt cap (`400`), a global daily budget cap of 100 scans per UTC day (`503`), and a per-IP rate limit of 5 scans per 5 minutes (`429`, with a computed `Retry-After`). All four bounds are env-configurable via `PROMPTSHIELD_WEB_MAX_PROMPT_CHARS`, `PROMPTSHIELD_WEB_DAILY_CAP`, `PROMPTSHIELD_WEB_IP_RATE`, and `PROMPTSHIELD_WEB_IP_WINDOW_SECONDS`. Client IP resolves from the leftmost `X-Forwarded-For` entry behind the platform proxy, falling back to the socket peer locally.
- **62 backend tests** (`backend/tests/`) covering health, the limiter, scan orchestration, and the SSE stream — alongside the existing 239-test engine suite. The limiter takes an injectable `time_fn` so rate-limit and day-rollover tests drive the clock with no real waiting.
- **Railway deploy config** (`railway.json`) and a fourth CI job, `Backend (clean prod install + tests)`, which installs the engine from the repo root the production way (`pip install .`) rather than editable, then runs the backend suite against it — so a packaging break that only shows up in a fresh environment fails CI instead of the deploy.
- **`docs/WEB_ARCHITECTURE.md`** recording the locked Phase 0 decisions: the 13-attack web set (Decision 1) and the target-plus-analyzer configuration (Decision 2).

### Changed

- Version is now single-sourced at `0.5.0` from `pyproject.toml`; `promptshield.__version__` resolves through `importlib.metadata`, and the backend reports that same value from `/api/health`.
- The README was rewritten for the public launch, leading with the live demo and a screenshot of a real results page.
- The web demo's leaky example prompt was strengthened so the demo reliably breaks — a launch demo that sometimes shows nothing is worse than no demo.
- Backend runtime dependencies are pinned (`fastapi==0.141.1`, `uvicorn==0.30.6`, `python-dotenv==1.2.2`) and the engine is installed separately from the repo root, removing the editable-parent hack from production builds.

### Fixed

- Bumped `fastapi` 0.115.0 → 0.141.1 and `python-dotenv` 1.0.1 → 1.2.2.
- Corrected drift between `docs/WEB_ARCHITECTURE.md` and the shipped implementation.

### Security

- Abuse controls run **before** the SSE stream opens, so a rejected request is a clean HTTP error that never reaches a model call — rate-limit rejections cost nothing.
- `/api/health` reports provider configuration as booleans only; no key material is ever returned.
- The scan result payload is a curated projection, not a raw dump: the only target output that leaves the server is a 600-character excerpt, and only for statuses where it is evidence.
- CORS defaults to local dev origins only; the deployed frontend origin is added only when `FRONTEND_URL` is set.
- Visitors' system prompts are used for the scan and not persisted.

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

[Unreleased]: https://github.com/SalCyberAware/PromptShield/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/SalCyberAware/PromptShield/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/SalCyberAware/PromptShield/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SalCyberAware/PromptShield/releases/tag/v0.3.0
