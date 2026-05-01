<div align="center">

# 🛡️ PromptShield

**Open-source vulnerability scanner for LLM applications**

Tests AI endpoints and web-based chatbots against the OWASP LLM Top 10, MITRE ATLAS techniques, and custom adversarial attacks.

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3b82f6?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Status](https://img.shields.io/badge/Status-Phase%201%20In%20Development-orange?style=for-the-badge)](#)

</div>

---

## What is PromptShield?

PromptShield is a free, open-source vulnerability scanner specifically designed for AI applications. While traditional scanners like Nessus and Qualys cover infrastructure, no equivalent exists for testing LLM-powered systems against prompt injection, data leakage, jailbreaks, and other AI-specific attacks.

PromptShield fills that gap.

**The Problem:** Companies are deploying LLMs everywhere but have no standardized way to test them for security vulnerabilities. Existing AI red-teaming requires expert humans, expensive consultants, or proprietary tools costing $50,000+/year.

**The Solution:** A community-driven, open-source scanner that automatically tests AI endpoints and applications against industry-standard frameworks (OWASP LLM Top 10, MITRE ATLAS) and produces audit-ready reports.

---

## Status

PromptShield is in active early development as part of an MS Cybersecurity practicum at Georgia Tech. Phase 1 (core CLI scanner) is currently being built.

### Roadmap

- **Phase 1** (in progress): Core CLI scanner with OWASP LLM Top 10 attack library
- **Phase 2**: Web application scanner (Playwright integration)
- **Phase 3**: Multi-model ensemble analysis engine
- **Phase 4**: Web UI and audit-ready reporting (PDF/HTML/SARIF)
- **Phase 5**: Research paper and empirical study of public AI applications

---

## Planned Features

- Tests AI API endpoints (OpenAI, Anthropic, Azure OpenAI, custom)
- Tests AI-powered web applications via Playwright
- OWASP LLM Top 10 coverage (10 categories)
- MITRE ATLAS technique mapping
- Multi-model ensemble analysis (Claude + GPT-4o-mini + optional local Llama 3)
- Confidence-weighted voting for low false positive rate
- Multiple report formats: JSON, HTML, PDF, CSV, SARIF
- Privacy-first: local-first design, zero data retention by default
- CLI for power users + Web UI for accessibility
- Encrypted credential storage
- Resume-from-checkpoint scanning
- GitHub Actions integration via SARIF

---

## Installation (Coming Soon)

```bash
pip install promptshield
```

For now, install from source:

```bash
git clone https://github.com/SalCyberAware/PromptShield.git
cd PromptShield
pip install -e ".[dev]"
```

---

## Quick Start (Planned CLI)

```bash
# Scan an API endpoint
promptshield scan --target https://api.example.com/chat --auth-type bearer --api-key XXX

# Scan a web chatbot
promptshield scan --target https://chatbot.example.com --type web

# Test specific OWASP categories
promptshield scan --target XXX --categories LLM01,LLM06

# Generate a report
promptshield report --scan-id abc123 --format pdf

# Browse the attack library
promptshield library list --category LLM01
```

---

## Why PromptShield?

### vs Manual Red Teaming
- **Manual:** Requires expert humans, slow, expensive, inconsistent
- **PromptShield:** Automated, fast, repeatable, contributable

### vs Commercial AI Security Tools
- **Commercial:** $50,000+/year, vendor lock-in, opaque methodology
- **PromptShield:** Free, open-source, transparent, community-driven

### vs Single-Model Testing
- **Single-model:** Bias from one analyzer, single point of failure
- **PromptShield:** Ensemble of Claude + GPT + local Llama with voting

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PromptShield CLI / Web UI                │
└────────────────────────────┬────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   Attack Library      Scanner Engine      Multi-Model
   (OWASP, ATLAS,      (API + Web)         Analysis Engine
   community)                              (Pattern + LLMs)
        │                    │                    │
        └────────────────────┼────────────────────┘
                             ▼
                       Report Generator
                  (JSON, PDF, HTML, SARIF)
```

---

## Tech Stack

- **Language:** Python 3.11+
- **CLI:** Click + Rich
- **API Scanning:** httpx (async)
- **Web Scanning:** Playwright
- **AI Analyzers:** Anthropic Claude, OpenAI GPT-4o-mini, optional Llama 3 via Ollama
- **Web Framework:** FastAPI + React/Vite (Phase 4)
- **Report Generation:** Jinja2, WeasyPrint
- **Data Models:** Pydantic v2

---

## Security and Privacy

PromptShield is built with security and privacy as first-class concerns:

- **Zero data retention** by default — no scan data stored unless explicitly enabled
- **No telemetry** — PromptShield never phones home
- **Local-first design** — works fully offline once attack library is downloaded
- **Encrypted credentials** at rest using AES-256 with user passphrase
- **Responsible disclosure** templates included
- **Ethical use only** — tool requires authorization to scan targets

---

## Compliance Alignment

- NIST AI Risk Management Framework (AI RMF)
- ISO 42001 (AI Management Systems)
- OWASP LLM Top 10
- MITRE ATLAS
- NIST 800-53 (where applicable)

---

## Contributing

Once Phase 1 stabilizes, contributions will be welcome — especially:
- New attacks for the library
- Additional analyzer integrations
- Documentation improvements
- Bug reports and feature requests

For now, watch the repo for progress.

---

## Author

**Salah-Adin Mozeb**
M.S. Cybersecurity — Georgia Tech (in progress)
CompTIA Security+ | Network+ | A+ | Cisco CCNA
GitHub: [@SalCyberAware](https://github.com/SalCyberAware)

Other security tools by this author:
- [ThreatScan](https://github.com/SalCyberAware/ThreatScan) — Multi-engine threat intelligence platform
- [SOCTriage](https://github.com/SalCyberAware/SOCTriage) — AI-powered SOC alert triage assistant

---

## License

**MIT** — free to use, modify, and distribute.

---

<div align="center">

Built as part of an MS Cybersecurity practicum at Georgia Tech.

[Report Issue](https://github.com/SalCyberAware/PromptShield/issues) · [Request Feature](https://github.com/SalCyberAware/PromptShield/issues)

</div>
