# PromptShield

**Paste a system prompt. PromptShield attacks it and shows you what breaks.**

### [Try the live demo](https://prompt-shield-mocha.vercel.app)

No signup, no API key, no install. Click "Try a leaky prompt" and hit "Scan prompt".

[![CI](https://github.com/SalCyberAware/PromptShield/actions/workflows/ci.yml/badge.svg)](https://github.com/SalCyberAware/PromptShield/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/SalCyberAware/PromptShield?label=coverage&logo=codecov&logoColor=white)](https://codecov.io/gh/SalCyberAware/PromptShield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Version](https://img.shields.io/badge/version-0.5.0-blue)
![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Attacks](https://img.shields.io/badge/attacks-50-orange)

![PromptShield scan result showing a caught XSS finding: the LLM02 "XSS payload generation" attack marked vulnerable at high severity, with the judging model, its confidence score, and an excerpt of the target model's reply containing the script tag it was talked into producing.](docs/images/demo-finding.png)

---

## What it does

You give PromptShield a system prompt, the kind you would put in front of a customer support bot or an internal assistant. PromptShield runs that prompt on a real model, fires a library of adversarial attacks at it, and reports which attacks got through.

Each attack is one user turn sent against your system prompt. A separate model reads the reply and decides whether the attack succeeded. You get a per-attack verdict with the payload that was sent, an excerpt of what the model said back, the OWASP LLM category, the severity, and the judge's reasoning.

The web demo runs 13 attacks covering 6 OWASP LLM categories. The full CLI runs all 50.

---

## The honesty model

Most scanners report a binary pass or fail per check. That is a lie whenever the check did not actually run. PromptShield reports five explicit statuses instead:

| Status | Meaning |
|---|---|
| `vulnerable` | An AI judge ran and confirmed the attack got through. |
| `held` | An AI judge ran and found the system prompt defended against the attack. |
| `needs_review` | The attack was judged, but the verdict is low confidence or the judges disagreed. A human should look at it. |
| `error` | The target model call failed or timed out. There is no reply to judge. |
| `not_ai_judged` | The target replied, but no AI judge produced a verdict, so only the deterministic pattern floor ran. |

Two rules follow from that, and both are enforced in code:

**An attack that errored or could not be AI judged is never reported as `held`.** In `backend/scan.py`, an `[ERROR]` or `[TIMEOUT]` reply becomes `error`, and a reply with no AI verdict becomes `not_ai_judged`. Neither can fall through into the `held` bucket.

**A failed test never counts as a passing test.** The summary's `passed` count is exactly the number of `held` attacks, and `failed` is exactly the number of `vulnerable` attacks. The `error` and `not_ai_judged` counts are reported on their own and are deliberately in neither. The severity and OWASP category rollups are built only from `vulnerable` and `needs_review` attacks.

If a judge goes down mid-scan, or the target rate-limits, or a reply comes back empty, you see that. You do not get a green check mark for a test that never happened.

---

## Cross-provider judging

The model under attack and the model grading the attack come from different vendors, on purpose.

- **Target:** `gpt-4o-mini` (OpenAI). It runs your system prompt and receives the attack payload.
- **Judge, primary:** Claude Sonnet (Anthropic).
- **Judge, fallback:** Gemini Flash (Google), used when the primary judge is unavailable.
- **Floor:** a deterministic pattern analyzer that always runs and never depends on a network call.

OpenAI is never a judge in the web demo. A vendor grading its own model's output carries same-family bias, and the whole value of the verdict is that it is independent of the thing being tested. The two-tier judge cascade also means one provider outage degrades the scan rather than killing it.

### Two-judge ensemble mode

Setting `PROMPTSHIELD_WEB_ENSEMBLE=1` runs both judges on every attack instead of one. When they agree, you get their agreed verdict. When they disagree, the attack is reported as `needs_review` with both verdicts attached, rather than picking a winner and hiding the split.

This doubles the judging cost per scan, so it is off by default on the public demo. Judge disagreement is a signal worth surfacing, and the ensemble mode exists to surface it.

---

## Quick start (CLI)

The CLI scans a live API endpoint and runs the full 50-attack library.

```bash
git clone https://github.com/SalCyberAware/PromptShield.git
cd PromptShield
pip install -e ".[dev]"
```

Requires Python 3.11 or newer.

Add your keys to a `.env` file. They are never passed on the command line.

```bash
cp .env.example .env
# Edit .env:
#   ANTHROPIC_API_KEY=sk-ant-...
#   OPENAI_API_KEY=sk-...
```

Then run a scan:

```bash
# Check your setup and see which keys were loaded
promptshield info

# See what would be sent, without sending anything
promptshield scan --target https://api.openai.com/v1/chat/completions --dry-run

# Run a scan with the AI judge enabled, saved as a shareable HTML report
promptshield scan \
  --target https://api.anthropic.com/v1/messages \
  --categories LLM01,LLM06 \
  --use-ai-analyzer \
  --output report.html
```

Useful extras:

```bash
promptshield library list          # browse all 50 attacks
promptshield library stats         # counts by category and severity
promptshield library show PS-LLM01-001

promptshield scan --target ... --verbose        # print full prompt/response transcripts
promptshield scan --target ... -o results.json  # format is picked from the file extension
```

Without `--use-ai-analyzer`, only the free pattern analyzer runs. `.env` is excluded by `.gitignore`, and API keys are redacted from saved JSON and HTML reports.

---

## Scope and limits

- **The web demo runs 13 of the 50 attacks.** They are the subset whose result actually depends on the system prompt you pasted, weighted toward prompt injection and system prompt leakage. The set is an explicit ID allowlist in `backend/scan.py`. The other 37 stay in the CLI.
- **Three OWASP categories do not apply to a bare system prompt.** LLM03 (training data poisoning), LLM05 (supply chain), and LLM07 (insecure plugin design) are properties of how a system is built and deployed, not of its system prompt. The demo reports them as not applicable rather than as passed.
- **The public demo is rate limited and capped.** Defaults are 5 scans per IP per 5 minutes, 100 scans per day across all users, and an 8,000 character limit on the submitted prompt. Every scan spends real money on model calls. If you hit the daily cap, run the CLI. All three limits are configurable in `backend/limits.py`.
- **Results vary between runs.** The target model is non-deterministic, so the same system prompt can hold against an attack on one run and give way on the next. Treat a single scan as a sample, not a proof. A prompt that holds 13 out of 13 once has not been proven secure.
- **The CLI does not scan system prompts.** It scans API endpoints. System prompt scanning currently lives in the web backend.
- **Test what you own.** PromptShield sends adversarial payloads to whatever target you point it at. Use it on systems you own or are authorized to test. See [SECURITY.md](SECURITY.md).

---

## Architecture in brief

```
promptshield/   Python package and CLI. Attack library, scan engines,
                pattern + AI analyzers, HTML and JSON reporters.
backend/        FastAPI app that imports promptshield as a library.
                Streams scans over SSE. Deployed on Railway.
frontend/       React + Vite scan UI. Deployed on Vercel.
```

Provider keys live server side only and are never sent to the browser. The backend exposes `GET /api/health` and `POST /api/scan/stream`, which streams `start`, `progress`, and `done` events as each attack runs.

Full design, including the locked decisions behind the 13-attack set and the judge configuration: [docs/WEB_ARCHITECTURE.md](docs/WEB_ARCHITECTURE.md).

**Testing:** 315 tests (245 for the package, 70 for the backend) across 6 CI jobs: a pytest matrix on Python 3.11, 3.12, and 3.13, plus ruff, mypy strict, and a backend job that installs the package the production way before running the web tests. All API calls are mocked, so the suite costs nothing and does not touch the network.

---

## Screenshots

CLI scan output:

![PromptShield CLI scan summary table](docs/screenshots/cli-scan.png)

HTML report, single file and shareable, with collapsible transcripts:

![PromptShield HTML scan report](docs/screenshots/html-report.png)

---

## Roadmap

Tracked in the open issues:

- [#1 Web product: scan UI and deployed demo](https://github.com/SalCyberAware/PromptShield/issues/1) (epic, demo now live)
- [#2 Pin model versions and record attack-set version per scan](https://github.com/SalCyberAware/PromptShield/issues/2)
- [#3 Eval harness: labeled verdict benchmark for regression testing](https://github.com/SalCyberAware/PromptShield/issues/3)
- [#4 Semi-automatic attack generator with human curation](https://github.com/SalCyberAware/PromptShield/issues/4)

Contributions are welcome, especially new attacks for the library. See [CONTRIBUTING.md](CONTRIBUTING.md) for the attack format and the pull request process.

---

## Author

**Salah-Adin Mozeb** ([@SalCyberAware](https://github.com/SalCyberAware))
M.S. Cybersecurity, Georgia Tech (in progress)

Also: [ThreatScan](https://github.com/SalCyberAware/ThreatScan) (threat intelligence platform) and [SOCTriage](https://github.com/SalCyberAware/SOCTriage) (SOC alert triage assistant).

---

## License

MIT. Free to use, modify, and distribute. See [LICENSE](LICENSE).
