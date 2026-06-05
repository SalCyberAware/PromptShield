# 🛡️ PromptShield

**Open-source vulnerability scanner for LLM applications**

*Tests AI endpoints and chatbots against the OWASP LLM Top 10, MITRE ATLAS techniques, and custom adversarial attacks.*

[![CI](https://github.com/SalCyberAware/PromptShield/actions/workflows/ci.yml/badge.svg)](https://github.com/SalCyberAware/PromptShield/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/SalCyberAware/PromptShield?label=coverage&logo=codecov&logoColor=white)](https://codecov.io/gh/SalCyberAware/PromptShield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Tests](https://img.shields.io/badge/tests-162%20passing-brightgreen)
![Attacks](https://img.shields.io/badge/attacks-50-orange)
![OWASP](https://img.shields.io/badge/OWASP%20LLM-Top%2010%20Coverage-purple)

---

## What is PromptShield?

PromptShield is a free, open-source vulnerability scanner specifically designed for AI applications. While traditional scanners like Nessus and Qualys cover infrastructure, no equivalent exists for testing LLM-powered systems against prompt injection, data leakage, jailbreaks, and other AI-specific attacks.

**PromptShield fills that gap.**

**The Problem:** Companies are deploying LLMs everywhere but have no standardized way to test them for security vulnerabilities. Existing AI red-teaming requires expert humans, expensive consultants, or proprietary tools costing $50,000+/year.

**The Solution:** A community-driven, open-source scanner that automatically tests AI endpoints against industry-standard frameworks (OWASP LLM Top 10, MITRE ATLAS) using a multi-analyzer ensemble approach for low false-positive rates.

---

## Status

**Phase 1 complete.** PromptShield has a working CLI scanner with 50 attacks covering all 10 OWASP LLM Top 10 categories, two complementary analyzers (pattern-based + Claude AI), HTML and JSON report generators, and a 162-test pytest suite running on Python 3.11, 3.12, and 3.13.

---

## Screenshots

### CLI scan output

![CLI scan summary](docs/screenshots/cli-scan.png)

### HTML report

Single-file, shareable, severity-coded, with collapsible transcripts:

![HTML scan report](docs/screenshots/html-report.png)

---

## Roadmap

- ✅ **Phase 1** (complete): Core CLI scanner with 50-attack OWASP LLM Top 10 library, multi-analyzer engine (Claude + GPT-4o-mini ensemble with cascading fallback), HTML/JSON reporting, pytest suite
- 🚧 **Phase 2** (next): Web application scanner via Playwright
- 📋 **Phase 4**: Web UI + advanced reporting (PDF / SARIF)
- 📋 **Phase 5**: Research paper and empirical study of public AI applications

---

## Features

### Working Today

- **50 attacks** covering all 10 OWASP LLM Top 10 categories
- **Multi-analyzer engine**: Pattern-based + Claude AI analyzers with confidence-weighted voting
- **OpenAI GPT-4o-mini analyzer with Claude→GPT cascading fallback**: secondary AI analyzer that runs when Claude is unavailable or returns an internal-error verdict
- **Multi-provider support**: Auto-detects Anthropic and OpenAI APIs
- **HTML reports**: shareable single-file output with severity-coded layout, summary cards, and collapsible transcripts
- **JSON reports**: machine-readable output with the same data, suitable for pipelines and SIEMs
- **Verbose mode**: Inspect full prompt/response transcripts for research
- **Secret redaction**: API keys automatically redacted from saved reports
- **Environment-based auth**: Loads API keys from `.env` (never on the command line)
- **MITRE ATLAS mapping**: Attacks tagged with corresponding ATLAS techniques where applicable
- **Rich CLI** with colored output, progress bars, and structured tables
- **Automatic retry**: transient API failures (rate limits, server errors, timeouts) are retried with exponential backoff
- **Graceful interruption**: Ctrl+C stops a scan cleanly instead of dumping a traceback

### Planned

- Web application scanning (Playwright)
- PDF / SARIF report formats
- Web UI dashboard
- GitHub Actions SARIF integration

---

## Installation

```bash
git clone https://github.com/SalCyberAware/PromptShield.git
cd PromptShield
pip install -e ".[dev]"
```

Requires Python 3.11+.

### Configure API Keys

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
# Edit .env and add:
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
```

**Never commit `.env` to source control.** PromptShield's `.gitignore` excludes it by default.

---

## Quick Start

```bash
# Show system info (verifies your API keys are loaded)
promptshield info

# Browse the attack library
promptshield library list
promptshield library stats
promptshield library show PS-LLM01-001

# Scan an API endpoint (pattern matching only, free)
promptshield scan --target https://api.anthropic.com/v1/messages --categories LLM10

# Scan with AI analyzer enabled (uses Claude for deeper semantic analysis)
promptshield scan --target https://api.anthropic.com/v1/messages \
  --categories LLM10 \
  --use-ai-analyzer \
  --verbose \
  --output scan_results.json

# Save the report as shareable HTML (format auto-detected from extension)
promptshield scan --target https://api.anthropic.com/v1/messages \
  --categories LLM10 \
  --use-ai-analyzer \
  --output report.html

# Dry-run to see what would be scanned
promptshield scan --target https://api.example.com --dry-run

# Scan specific OWASP categories
promptshield scan --target https://api.example.com --categories LLM01,LLM06
```

---

## Attack Library

PromptShield ships with **50 attacks** across all OWASP LLM Top 10 categories:

| Category | Description | Count |
|----------|-------------|-------|
| LLM01 | Prompt Injection | 10 |
| LLM02 | Insecure Output Handling | 5 |
| LLM03 | Training Data Poisoning | 3 |
| LLM04 | Model Denial of Service | 5 |
| LLM05 | Supply Chain Vulnerabilities | 3 |
| LLM06 | Sensitive Information Disclosure | 6 |
| LLM07 | Insecure Plugin Design | 3 |
| LLM08 | Excessive Agency | 5 |
| LLM09 | Overreliance | 3 |
| LLM10 | Model Theft | 3 |
| CUSTOM | PromptShield Research | 4 |

**Severity distribution:** 2 critical · 21 high · 21 medium · 6 low

Attacks reference real research (CVE-2021-44228 Log4Shell, Greshake et al. 2023, Zou et al. 2023, Carlini et al. training data extraction) and include remediation guidance for each finding.

---

## Multi-Analyzer Architecture

PromptShield uses two complementary analyzers that vote on whether an attack succeeded:

```
Target's Response
       │
       ├──→ PatternAnalyzer (fast, free, deterministic)
       │       └─ Regex/keyword matching against expected indicators
       │
       └──→ ClaudeAnalyzer (slower, costs ~$0.003 per call, semantic)
               └─ Claude evaluates whether the attack succeeded
                                                    │
       Combined Verdict ←──────────────────────────┘
       (both analyzers agree = HIGH confidence finding)
       (analyzers disagree = MEDIUM confidence, flagged for review)
       (neither detects = no finding)
```

### Why this matters

In testing against Anthropic's Claude API on the three LLM10 (model theft) attacks, **pattern-only detection correctly identified 2 of 3 attacks**. Adding the Claude AI analyzer recovered the missed attack (`PS-LLM10-002` capability mapping) — but the two analyzers *disagreed* on it. Confidence-weighted voting correctly produced a **medium-confidence finding (57%) flagged for manual review**, rather than either silently dropping it (false negative) or pretending the verdict was certain (false positive).

This is empirical evidence that pure pattern matching has measurable false-negative rates, and that ensemble approaches with explicit disagreement-handling do two useful things at once: they reduce missed detections, and they route uncertain cases to humans instead of overclaiming confidence.

This finding will be cited in the eventual research paper.

---

## Testing

PromptShield has a comprehensive pytest suite that runs on every push via GitHub Actions:

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=promptshield --cov-report=term-missing
```

**Current status:** 162 tests passing in ~4 seconds, with 93% overall coverage.

| Module | Coverage |
|--------|----------|
| `models.py` | 100% |
| `analyzers/pattern.py` | 100% |
| `analyzers/claude_analyzer.py` | 88% |
| `attacks/library.py` | 96% |
| `reporters/json_reporter.py` | 96% |
| `reporters/html_reporter.py` | 100% |
| `engines/api_scanner.py` | 75% |
| `engines/base.py` | 98% |
| `cli.py` | 93% |

All HTTP calls and API interactions are mocked in tests — no real API calls, no costs, no flaky network dependencies.

---

## Architecture

```
PromptShield/
├── promptshield/
│   ├── cli.py                  # Click + Rich command-line interface
│   ├── models.py               # Pydantic data models
│   ├── attacks/
│   │   ├── library.py          # Attack library loader and filtering
│   │   └── data/attacks_v1.yaml
│   ├── analyzers/
│   │   ├── pattern.py          # Fast pattern-based analyzer
│   │   └── claude_analyzer.py  # AI-powered semantic analyzer
│   ├── engines/
│   │   ├── base.py             # Multi-analyzer orchestration
│   │   └── api_scanner.py      # Multi-provider API scanner
│   └── reporters/
│       ├── html_reporter.py    # HTML output (Jinja2 template, redacted)
│       ├── json_reporter.py    # JSON output with secret redaction
│       └── templates/
│           └── scan_report.html.j2
└── tests/                      # 162 pytest tests
```

---

## Tech Stack

- **Language:** Python 3.11+
- **CLI:** Click + Rich
- **API Scanning:** httpx (async)
- **Web Scanning (Phase 2):** Playwright
- **AI Analyzers:** Anthropic Claude (working), OpenAI GPT-4o-mini (working)
- **Reporting:** JSON (stdlib) + HTML (Jinja2)
- **Web Framework (Phase 4):** FastAPI + React/Vite
- **Data Models:** Pydantic v2
- **Testing:** pytest, pytest-asyncio, pytest-cov

---

## Security and Privacy

PromptShield is built with security and privacy as first-class concerns:

- **Zero data retention** by default — no scan data stored unless explicitly enabled
- **No telemetry** — PromptShield never phones home
- **Automatic secret redaction** — API keys and credentials redacted from JSON and HTML outputs
- **Local-first design** — works fully offline once attack library is loaded
- **Environment-based auth** — API keys loaded from `.env`, never required on the command line
- **Responsible use only** — tool is designed for testing systems you own or have authorization to test

See [SECURITY.md](SECURITY.md) for the full vulnerability disclosure policy.

### Compliance Alignment

- NIST AI Risk Management Framework (AI RMF)
- ISO 42001 (AI Management Systems)
- OWASP LLM Top 10
- MITRE ATLAS
- NIST 800-53 (where applicable)

---

## Contributing

Contributions are welcome — especially:

- **New attacks** for the library (highest impact, low barrier to entry)
- Additional analyzer integrations
- Documentation improvements
- Bug reports and feature requests

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on the attack contribution format and pull request process.

---

## Why PromptShield?

### vs Manual Red Teaming
- **Manual:** Requires expert humans, slow, expensive, inconsistent
- **PromptShield:** Automated, fast, repeatable, community-contributable

### vs Commercial AI Security Tools
- **Commercial:** $50,000+/year, vendor lock-in, opaque methodology
- **PromptShield:** Free, open-source, transparent, community-driven

### vs Single-Model Testing
- **Single-model:** Bias from one analyzer, single point of failure
- **PromptShield:** Ensemble of pattern matching + Claude AI with confidence-weighted voting

---

## Author

**Salah-Adin Mozeb**
M.S. Cybersecurity — Georgia Tech (in progress)
CompTIA Security+ | Network+ | A+ | Cisco CCNA
GitHub: [@SalCyberAware](https://github.com/SalCyberAware)

### Other open-source security tools by this author

- **[ThreatScan](https://github.com/SalCyberAware/ThreatScan)** — Multi-engine threat intelligence platform
- **[SOCTriage](https://github.com/SalCyberAware/SOCTriage)** — AI-powered SOC alert triage assistant

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).
