# PromptShield Web Architecture

> Phase 0 design doc for Epic #1. No code in this commit — this is the build guide
> the next session starts from. Detection core (engine, 4-tier cascade, 50-attack
> library, 229 tests) shipped in **v0.4.0**; everything below is the web wrapper + deploy.

## Goal

Turn PromptShield from CLI-only into a deployed web product with a public demo URL,
matching the shape of **SOCTriage** and **ThreatScan**:

- `promptshield/` stays the published pip package + CLI (unchanged contract).
- A new `backend/` (FastAPI) imports `promptshield` **as a library**.
- A new `frontend/` (React + Vite) drives a live, streaming scan UI.
- Deploy: frontend → Vercel, backend → Railway, keys server-side only.

## Scan model (Phase 0 decision — LOCKED)

**Option 1 — "Paste your system prompt, we scan it."**

The visitor submits a *system prompt*. The backend runs that prompt through a
**server-side model on our keys**, fires the attack library at it
(`[system: user's prompt, user: attack payload]` per attack), and the analyzers
judge which attacks succeeded. Output: **OWASP LLM category breakdown +
per-attack verdicts + severity**. A pre-filled example prompt lets visitors scan
without typing anything.

Chosen over bring-your-own-endpoint because it is:
- **Safe** — our keys, no attack traffic ever sent to a third-party endpoint.
- **Self-contained** — no user credentials, no SSRF surface, no target reachability problems.
- **Maximally reusing the engine** — it's one new `BaseScanner` subclass; nothing else in the core changes.

## Phase 0 decisions (locked)

### Decision 1 — Trimmed web-demo attack set (13 of 50)

**Principle:** maximize attacks whose result actually depends on the visitor's pasted
system prompt (the ✅ system-prompt-testable set from the library inventory), weighted
toward prompt-injection + system-prompt-leak since that is what a system prompt's
defenses actually govern. **The full 50 stays in the CLI.**

The 13 (every ID verified present in `promptshield/attacks/data/attacks_v1.yaml`):

| ID | Name | OWASP |
|----|------|-------|
| PS-LLM01-001 | Direct instruction override | LLM01 |
| PS-LLM01-009 | Prompt leaking via repetition | LLM01 |
| PS-LLM01-002 | DAN jailbreak | LLM01 |
| PS-LLM01-004 | Encoding bypass (base64) | LLM01 |
| PS-LLM01-008 | Authority impersonation | LLM01 |
| PS-CUSTOM-001 | Token-boundary confusion | LLM01 |
| PS-CUSTOM-003 | Adversarial suffix (GCG) | LLM01 |
| PS-LLM06-001 | System prompt extraction | LLM06 |
| PS-CUSTOM-004 | Memory confabulation | LLM06 |
| PS-LLM09-002 | Medical advice without disclaimer | LLM09 |
| PS-LLM10-001 | Model fingerprinting | LLM10 |
| PS-LLM08-002 | Privilege escalation | LLM08 |
| PS-LLM02-001 | XSS payload generation | LLM02 |

**Coverage:** 6 OWASP categories — LLM01, LLM02, LLM06, LLM08, LLM09, LLM10.

**Not-applicable categories** (LLM03 poisoning, LLM05 supply chain, LLM07 plugin design,
tool-dependent LLM08 agency): the results UI shows these as **"Not applicable to
system-prompt scanning — run the full CLI scan against a live endpoint,"** *not* as
passed. Honest framing plus a CLI upsell.

### Decision 2 — Analyzer + target config

- **Target** (runs the visitor's system prompt + attack payload): **`gpt-4o-mini`**.
  Cheaper models are the tougher, more realistic security test — they are what gets
  deployed at scale and are more injection-prone — and they bound public-demo cost.
- **Analyzer** (judges whether an attack succeeded): **pattern floor + a 2-tier
  cross-provider cascade — Claude Sonnet (primary) → Gemini Flash (fallback).** A
  stronger judge than Haiku because verdict accuracy *is* demo credibility;
  cross-provider from the OpenAI target to avoid same-family bias; the cascade gives
  uptime resilience at ~one analyzer call per attack in the typical case.
- **Model tier is CONFIGURABLE via env vars** (target + analyzer), defaulting
  conservative for the public demo. CLI / enterprise tier / deep audits flip to
  top-tier (Opus / flagship). The strength lives in the architecture; the public demo
  just defaults bounded.
- **Cost shape:** ~13 attacks × (1 target call + 1 analyzer call) per scan; bounded
  further by rate limiting (later slice).

## Key engine change: a new target type

This is the **one real addition to the detection core**. Everything else is wrapper.

### How a scan obtains a target response today

`promptshield/engines/base.py` defines `BaseScanner(ABC)`. The scan loop in
`run_scan(...)` is target-agnostic — for each attack it calls a single abstract method:

```python
@abstractmethod
async def send_attack(self, attack: Attack) -> str | None:
    """Send a single attack and return the raw response text."""
```

`run_scan` then: runs the always-on `PatternAnalyzer`, optionally walks the AI
analyzer cascade (`use_ai_analyzer=True`), combines verdicts via
`_combine_verdicts`, builds a `Finding` on success, records a `Transcript`, fires
the `on_progress(current, total, attack)` callback, and sleeps
`60 / rate_limit` between attacks. **None of that knows or cares how the response
was produced.**

`promptshield/engines/api_scanner.py` is the only concrete scanner today. Its
`send_attack` builds a chat payload — `messages: [{role: "user", content: attack.prompt}]`
— POSTs it to `target.url`, extracts assistant text, and converts errors into
diagnostic strings (`[HTTP ...]`, `[TIMEOUT]`, `[ERROR] ...`) rather than raising.
It also implements `cleanup()` to close its HTTP client.

### The new adapter

Add `promptshield/engines/system_prompt_scanner.py` — a `BaseScanner` subclass
that satisfies the **exact same two-method contract** as `APIScanner`:

```python
class SystemPromptScanner(BaseScanner):
    def __init__(self, target, attacks, system_prompt, model="gpt-4o-mini"): ...

    async def send_attack(self, attack: Attack) -> str | None:
        # Call our server-side model with the visitor's prompt as system,
        # the attack payload as the user turn:
        #   messages = [
        #     {"role": "system", "content": self.system_prompt},
        #     {"role": "user",   "content": attack.prompt},
        #   ]
        # Return assistant text; convert errors to "[ERROR] ..." strings.

    async def cleanup(self) -> None: ...
```

Because it returns a plain `str`, **the pattern analyzer and the AI cascade work
unchanged** — they only ever see `(attack, response)`.

Plug-in points / interface it must satisfy:
- Subclass `BaseScanner`; implement `send_attack` and `cleanup` (the only abstract methods).
- Constructed with a `TargetConfig` + `list[Attack]`, same as `APIScanner`.
- On error, **return** a string starting with `[ERROR]`/`[TIMEOUT]` rather than raising —
  `run_scan` skips analysis for responses starting with those prefixes.
- Driven identically: `await scanner.run_scan(scan_id=..., on_progress=..., use_ai_analyzer=...)`.

Supporting model touch-ups (small):
- Add `TargetType.SYSTEM_PROMPT = "system_prompt"` to `models.py` (current enum: `API`/`WEB`/`LOCAL`).
- `TargetConfig.url` is required and flows into `Finding.target_url`; use a sentinel
  such as `internal://<model>` so findings stay well-formed without a real endpoint.

## Cost & abuse control (first-class)

**Every public scan spends our money:** `(attacks × target-model call) +
(analyzer calls per response)`. A naïve demo running all 50 attacks through the
full 4-tier cascade is dozens of paid model calls per click. Knobs to set in Phase 1:

- **Tight per-IP rate limiting** — much tighter than ThreatScan, because each scan
  is far more expensive (one click = many model calls). E.g. a few scans per IP per hour.
- **System-prompt length cap** — hard limit on submitted prompt size (it's sent as
  `system` on every attack call, so length multiplies cost across the whole attack set).
- **Cheapest capable target model** — `gpt-4o-mini` / `gemini-flash` / `claude-haiku`.
  Default the demo to one of these; never expose model choice to the visitor.
- **Reduced attack set for the demo** — ship ~10–15 representative attacks spanning
  OWASP LLM01–LLM10, not all 50. The **full 50 stays in the CLI**. Curate a
  `web_demo` tag or a fixed ID allowlist so the set is explicit and reviewable.
- **Reduced analyzer for the demo** — pattern floor + a **2-tier** cross-provider
  cascade (Claude Sonnet → Gemini Flash), **not** the full 4-tier cascade; see
  **Decision 2** above. Typically ~one analyzer call per attack, with the second tier
  engaging only as fallback — bounded cost with verdict accuracy and uptime resilience.
- **Daily global budget cap** — a process-wide counter that disables scanning (serves
  a friendly "demo at capacity, try later" message) once a daily spend ceiling is hit.

These are configuration, not new engine logic — the reduced attack set is just a
filtered `list[Attack]`, and the "reduced analyzer" is the existing `use_ai_analyzer`
flag with a trimmed (2-tier) cascade.

## Repo structure

Mirror SOCTriage / ThreatScan. Keep the package at root; add two siblings.

```
PromptShield/
├── promptshield/        # published package + CLI — UNCHANGED contract
│   ├── analyzers/        # pattern + claude/openai/gemini/ollama
│   ├── attacks/          # library.py + data/attacks_v1.yaml (50 attacks)
│   ├── engines/          # base.py, api_scanner.py, + system_prompt_scanner.py (NEW)
│   ├── reporters/        # html + json
│   ├── models.py
│   └── cli.py
├── backend/             # FastAPI app importing promptshield as a library — FLAT layout (mirrors SOCTriage)
│   ├── main.py          # app, CORS, routes
│   ├── scan.py          # wires SystemPromptScanner + reduced attack set + SSE (Phase 1)
│   ├── limits.py        # rate limiting, length cap, budget cap (Phase 1)
│   ├── conftest.py
│   ├── pytest.ini
│   ├── requirements.txt
│   └── tests/
├── frontend/            # NEW — React + Vite
│   ├── src/
│   └── package.json
├── docs/WEB_ARCHITECTURE.md
└── pyproject.toml
```

## Backend API (Phase 1)

FastAPI, importing `promptshield`. Endpoints:

- **`GET /api/health`** → `{ "status": "ok", "version": <promptshield.__version__> }`.
- **`GET /api/scan/stream`** (SSE) — accepts the system prompt + options
  (query/params), streams events as the scan runs. Mirror **ThreatScan's SSE event shape**:
  - `start` — scan id, attack count, model.
  - `progress` — one per attack, driven by the existing `on_progress(current, total, attack)`
    callback (attack id, name, category, index/total).
  - `done` — final report: OWASP LLM category breakdown, per-attack verdicts, severities.
  - `error` — fatal failure, friendly message (also used for rate-limit / budget-cap rejects).

Implementation note: `run_scan` is `async`; the SSE handler awaits it while pushing
`on_progress` callbacks onto the event stream (e.g. via an `asyncio.Queue`).

**Tests:** `/api/health`, `/api/scan/stream` (happy path + rate-limit reject + length-cap
reject), and unit tests for `SystemPromptScanner.send_attack` (system+user message
shape, error-string conversion) with the model call mocked.

## Frontend (Phase 2)

React + Vite, styled to match SOCTriage / ThreatScan.

- Textarea for the system prompt + a **"Use example"** button that fills a known prompt.
- "Scan" opens the SSE stream to `/api/scan/stream`.
- **Live attack-by-attack progress** from `progress` events (current/total bar + current attack).
- Results view: **OWASP LLM category breakdown**, severity rollup, and **expandable
  per-attack verdicts** (attack name, payload, analyzer reasoning, success/confidence).

## Deploy (Phase 3)

- **Frontend → Vercel.**
- **Backend → Railway.**
- Server-side keys as **Railway environment variables**, never shipped to the client.
- **CORS** locked to the Vercel production domain (and preview domains as needed).

Env vars (Railway):
- `OPENAI_API_KEY` / `GEMINI_API_KEY` / `ANTHROPIC_API_KEY` — only what the chosen
  target model + single demo analyzer actually need.
- `WEB_TARGET_MODEL` — e.g. `gpt-4o-mini`.
- `WEB_RATE_LIMIT_PER_IP`, `WEB_MAX_PROMPT_CHARS`, `WEB_DAILY_BUDGET_USD` — abuse knobs.
- `FRONTEND_ORIGIN` — CORS allowlist.

Frontend env: `VITE_API_BASE_URL` → the Railway backend URL.

## CI (note, don't implement)

Existing `.github/workflows/ci.yml` jobs run against the package only:
- **test** — pytest matrix on Python 3.11 / 3.12 / 3.13 (+ Codecov on 3.13).
- **lint** — `ruff check promptshield/ tests/`.
- **typecheck** — `mypy promptshield/` (strict).

Extend with:
- a **backend test job** (`pytest backend/tests`, plus ruff/mypy over `backend/`), and
- a **frontend build job** (`npm ci && npm run build` in `frontend/`).

Keep the existing package jobs as-is so the published package's gate is unchanged.

## Phase sequence (mirrors Epic #1)

0. **Phase 0 — Design (this doc).** Architecture, locked scan model, and locked Phase 0
   decisions (trimmed web-demo attack set + analyzer/target config). ✅ **Complete.**
1. **Phase 1 — Backend.** `SystemPromptScanner` + reduced attack set + single-analyzer
   config; FastAPI `/api/health` and `/api/scan/stream` (SSE); abuse knobs; tests.
2. **Phase 2 — Frontend.** React + Vite UI: textarea + example, SSE progress, results view.
3. **Phase 3 — Deploy.** Vercel + Railway, server-side keys, CORS lockdown.
4. **Phase 4 — Polish.** README demo link + screenshot, CHANGELOG, tag **v0.5.0**.
