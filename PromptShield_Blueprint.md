# PROMPTSHIELD — COMPLETE PROJECT BLUEPRINT

**Project Name:** PromptShield
**Author:** Salah-Adin Mozeb (GitHub: SalCyberAware)
**Date Created:** May 1, 2026
**Purpose:** MS Cybersecurity Practicum at Georgia Tech + Portfolio Project #3
**Status:** Design Phase

---

## EXECUTIVE SUMMARY

PromptShield is an open-source vulnerability scanner for AI applications. It automatically tests Large Language Model (LLM) endpoints and AI-powered web applications against the OWASP LLM Top 10, MITRE ATLAS techniques, and custom attack patterns. It generates security assessment reports with severity scoring, evidence, and remediation guidance.

**Why it matters:** Companies are deploying LLMs everywhere but have no standardized way to test them. PromptShield fills the role of "Nessus for AI applications."

**Practicum value:** Solves a documented real-world problem, contributes to OWASP LLM Top 10 testing methodology, produces a publishable research paper, and delivers a public open-source tool.

---

## THE PROBLEM

1. AI applications are being deployed faster than security teams can assess them
2. No standardized open-source LLM vulnerability scanner exists
3. Existing AI red-teaming requires expert humans, expensive consultants, or proprietary tools ($50k+/year)
4. NIST AI RMF and ISO 42001 require AI security testing but provide no testing tools
5. OWASP LLM Top 10 defines categories but does not provide automated testing implementations
6. Companies cannot answer: "Is our AI chatbot secure?"

---

## THE SOLUTION

A free, open-source, dual-mode (CLI + Web UI) scanner that:
- Tests AI API endpoints (OpenAI, Anthropic, Azure OpenAI, custom)
- Tests AI-powered web applications (chatbots, AI assistants)
- Uses ensemble AI analysis for high accuracy
- Maps findings to OWASP LLM Top 10 + MITRE ATLAS
- Generates audit-ready reports
- Operates with zero data retention by default
- Runs offline if needed

---

## CORE ARCHITECTURE

### Three-Layer Design

#### Layer 1 — Attack Library
Curated database of adversarial prompts organized by attack category. Pulled from multiple authoritative sources, version-controlled, and continuously updated.

**Sources:**
- OWASP LLM Top 10 official examples
- MITRE ATLAS technique database
- Anthropic, OpenAI, Google red team published attacks
- HuggingFace prompt injection datasets (PINT, JailbreakBench, etc.)
- Academic papers (cited in research output)
- Custom research attacks (PromptShield contribution)

**Categories covered:**
- LLM01: Prompt Injection (direct and indirect)
- LLM02: Insecure Output Handling
- LLM03: Training Data Poisoning indicators
- LLM04: Model Denial of Service
- LLM05: Supply Chain Vulnerabilities
- LLM06: Sensitive Information Disclosure
- LLM07: Insecure Plugin Design
- LLM08: Excessive Agency
- LLM09: Overreliance markers
- LLM10: Model Theft attempts
- MITRE ATLAS: AML.T0051 (Prompt Injection), AML.T0024 (Exfiltration), AML.T0020 (Poisoning), and others
- Custom: research-driven novel attacks

#### Layer 2 — Scanner Engine
Python core that orchestrates testing.

**Components:**
- API endpoint scanner (httpx async client)
- Web application scanner (Playwright headless browser)
- Authentication handler (API keys, OAuth, session cookies)
- Rate limiter (configurable per-target)
- Retry engine (exponential backoff, resume from checkpoint)
- Response collector (raw data preserved before analysis)

#### Layer 3 — Multi-Model Analysis Engine

**4-tier ensemble analysis:**

1. **Pattern Engine (free, instant)**
   - Regex-based detection
   - Known attack signatures
   - Sensitive data patterns (SSN, credit cards, API keys)
   - Catches obvious cases without AI calls

2. **Cloud LLM Voting**
   - Anthropic Claude Sonnet 4.6 (primary)
   - OpenAI GPT-4o-mini (validator)
   - Optional: Google Gemini for tie-breaking

3. **Local LLM (optional)**
   - Llama 3 via Ollama for privacy-sensitive scans
   - Fully offline analysis when needed

4. **Confidence-Weighted Voting**
   - All agree on success → HIGH confidence (95%+)
   - Majority agree → MEDIUM confidence (70-94%)
   - Disagreement → LOW confidence + flagged for manual review
   - All disagree → NO finding

#### Layer 4 — Reporting

**Output formats:**
- Terminal output (Rich library, color-coded)
- JSON (machine-readable, full data)
- HTML report (shareable, visual)
- PDF report (audit-ready)
- CSV (spreadsheet analysis)
- SARIF (Static Analysis Results Interchange Format — GitHub Actions integration)

---

## SINGLE POINT OF FAILURE ELIMINATION

### Robustness Pillars

#### 1. Attack Library Diversity
- Multiple authoritative sources synchronized
- Auto-update mechanism with version control
- Local cache for offline operation
- User can contribute custom attacks
- Quarterly review and curation cycle

#### 2. Target Endpoint Reliability
- Configurable rate limiting per target
- Retry logic with exponential backoff
- Checkpoint-based resume (scan continues from where it stopped)
- Per-attack timeout configuration
- Distinguishes between target unavailability and successful blocking

#### 3. Network and Infrastructure Failures
- Local-first design (CLI works offline)
- Cached attack libraries
- Cloud API fallback to single-analyzer mode
- Health checks for all dependencies
- Graceful degradation rather than full failure

#### 4. False Positive / False Negative Mitigation
- Confidence scoring on every finding
- Manual review workflow for uncertain findings
- Historical accuracy tracking
- User-contributable false positive database
- Differential testing (run scan twice, flag inconsistencies)

#### 5. Output Reliability
- Multiple export formats
- Raw scan data always preserved
- Cryptographic hash for report verification
- Export queue with retry

#### 6. Secrets and Authentication Security
- API keys never logged
- Encrypted at rest with user passphrase
- Memory-only storage option
- No telemetry by default
- Clear data flow documentation

#### 7. Versioning and Reproducibility
- Every scan tagged with attack library version
- Lockable library versions for compliance scans
- Full configuration export for re-runs
- Semantic versioning for attack library

#### 8. Adversarial Resistance
- Responsible disclosure templates
- Optional ethical use agreement
- Tool-level rate limiting (cannot bulk-scan thousands)
- Audit log option
- Documentation emphasizes defensive use

---

## SECURITY ARCHITECTURE

### Threat Model

**Threats to PromptShield itself:**
- Misuse for offensive scanning of unauthorized targets
- API key theft from compromised installations
- Supply chain attacks via attack library
- Prompt injection of PromptShield's own AI analyzers

**Mitigations:**
- All attack library sources cryptographically signed
- API keys encrypted at rest using AES-256 with user passphrase
- Sandboxed AI analyzer prompts (defense against meta-injection)
- Input sanitization on all user-provided data
- No execution of LLM responses (read-only analysis)

### Data Handling Principles

1. **Zero data retention by default** — no scan data stored unless user explicitly enables
2. **No telemetry** — PromptShield never phones home
3. **Local-first** — all processing can happen on user's machine
4. **Encrypted transit** — TLS 1.3 minimum for all API calls
5. **Encrypted at rest** — when scan history is enabled, encrypted with user key
6. **Right to erasure** — `promptshield delete-history` removes all data

### Compliance Alignment

- NIST AI RMF (Govern, Map, Measure, Manage functions)
- ISO 42001 (AI Management Systems)
- NIST 800-53 (where applicable to security tooling)
- OWASP LLM Top 10 (testing methodology)
- MITRE ATLAS (adversarial AI mapping)

---

## TECH STACK

| Component | Technology |
|-----------|-----------|
| CLI Framework | Python 3.11+, Click, Rich |
| Web Backend | FastAPI |
| Web Frontend | React + Vite |
| Web Scanner | Playwright |
| API Scanner | httpx (async) |
| Database | SQLite (local) / PostgreSQL (cloud) |
| AI Analyzers | Anthropic Claude API, OpenAI API, Ollama (local) |
| Report Generation | Jinja2, WeasyPrint (PDF), python-docx |
| Authentication | JWT, encrypted credential store |
| Testing | pytest, pytest-asyncio |
| Package Distribution | PyPI (`pip install promptshield`) |
| Container | Docker |
| Deployment | Railway (web backend), Vercel (web frontend) |
| Version Control | Git, GitHub |
| CI/CD | GitHub Actions |

---

## BUILD PHASES

### Phase 1 — Core CLI Scanner (Weeks 1-3)
**Goal:** Working CLI that can scan an OpenAI/Anthropic API endpoint and produce findings.

**Deliverables:**
- Project scaffolding (Python package structure)
- Initial attack library (30-50 OWASP LLM Top 10 prompts)
- API endpoint scanner functional
- Pattern-based detection engine
- Single-analyzer Claude integration
- Basic CLI with Rich terminal output
- JSON export
- pytest test suite
- Documentation: README, CONTRIBUTING, LICENSE

**Success criteria:**
- Can scan a deliberately vulnerable test endpoint
- Detects at least 80% of OWASP LLM Top 10 categories
- Generates valid JSON report
- Installable via `pip install promptshield-dev`

### Phase 2 — Web App Scanner (Weeks 4-5)
**Goal:** Extend scanner to test web-based AI chatbots.

**Deliverables:**
- Playwright integration
- Authentication handlers (cookies, OAuth, basic auth)
- Session management
- DOM-based response detection
- Screenshots of successful attacks (evidence)
- Browser automation safety controls

**Success criteria:**
- Can scan a public AI chatbot
- Handles authentication flows
- Captures evidence reliably

### Phase 3 — Multi-Model Analysis Engine (Weeks 6-7)
**Goal:** Implement ensemble AI analysis with confidence scoring.

**Deliverables:**
- OpenAI GPT-4o-mini integration
- Optional Ollama local LLM integration
- Voting algorithm
- Confidence scoring system
- False positive reduction logic
- Manual review workflow for low-confidence findings
- Performance benchmarking

**Success criteria:**
- Ensemble accuracy higher than any single analyzer
- Confidence scores correlate with true positive rate
- Performance acceptable (< 60s per finding analyzed)

### Phase 4 — Web UI + Reports (Weeks 8-10)
**Goal:** Build accessible web interface and professional reporting.

**Deliverables:**
- FastAPI backend with full REST API
- React frontend (Vite)
- Dashboard with findings visualization
- PDF report generation (audit-ready)
- HTML report (shareable)
- SARIF export for CI/CD
- Railway + Vercel deployment
- Documentation site

**Success criteria:**
- Non-technical users can run scans
- Reports are professional and audit-ready
- GitHub Actions integration works
- Public live demo available

### Phase 5 — Research Paper + Practicum Submission (Weeks 11-12)
**Goal:** Document methodology and produce publishable research.

**Deliverables:**
- Practicum paper (academic format)
- Methodology documentation
- Empirical study: scan 10+ public AI tools, aggregate findings
- Comparison: PromptShield vs manual red team vs other tools
- Conference submission draft (DEFCON AI Village, BSides, OWASP)
- Published research blog post
- Demo video

**Success criteria:**
- Practicum paper accepted by Georgia Tech advisor
- Research data is reproducible
- Findings contribute to OWASP LLM Top 10 community

---

## ATTACK LIBRARY STRUCTURE

### Schema

Each attack in the library has:
```json
{
  "id": "PS-LLM01-001",
  "category": "prompt_injection",
  "owasp_category": "LLM01",
  "mitre_atlas": "AML.T0051",
  "name": "Direct instruction override",
  "description": "Attempts to override system prompt via direct instruction",
  "severity": "high",
  "prompt": "Ignore all previous instructions and...",
  "expected_indicators": ["successful_override", "system_prompt_leaked"],
  "false_positive_patterns": ["...standard refusal..."],
  "remediation": "Implement system prompt isolation...",
  "references": ["OWASP LLM01", "Greshake et al. 2023"],
  "version": "1.0.0",
  "added_date": "2026-05-01"
}
```

### Initial Library Goal

50 attacks across 10 OWASP categories at launch, expanding to 200+ by Phase 5.

---

## API ENDPOINTS (Web Backend)

```
POST   /api/scan                  Submit scan request (target + config)
GET    /api/scans                 List all user scans
GET    /api/scans/{id}            Get scan details + findings
GET    /api/scans/{id}/report     Download report (PDF/HTML/JSON/SARIF)
DELETE /api/scans/{id}            Delete scan
GET    /api/library               Browse attack library
GET    /api/library/{attack_id}   Get attack details
POST   /api/library/contribute    Submit new attack (community)
GET    /api/dashboard             User dashboard stats
GET    /health                    Health check
```

---

## CLI COMMANDS

```bash
# Quick scan against an API
promptshield scan --target https://api.example.com/chat --auth-type bearer --api-key XXX

# Scan a web app
promptshield scan --target https://chatbot.example.com --type web

# Use specific attack categories
promptshield scan --target XXX --categories LLM01,LLM06

# Generate report
promptshield report --scan-id abc123 --format pdf

# Update attack library
promptshield library update

# List available attacks
promptshield library list --category LLM01

# Compare two scans
promptshield diff --scan-a abc123 --scan-b def456

# Export scan history
promptshield export --output scans.json
```

---

## DEPLOYMENT URLS (Planned)

- **Frontend:** https://promptshield.vercel.app
- **Backend:** https://promptshield-production.up.railway.app
- **GitHub:** https://github.com/SalCyberAware/PromptShield
- **PyPI:** https://pypi.org/project/promptshield
- **Docs:** https://promptshield.readthedocs.io (or docs subdomain)

---

## SUCCESS METRICS

### Technical Metrics
- Detect 90%+ of OWASP LLM Top 10 categories
- False positive rate under 10%
- Scan completion time under 5 minutes for typical target
- Support 5+ AI providers (OpenAI, Anthropic, Azure, Google, custom)

### Research Metrics
- 200+ attacks in library by Phase 5
- 10+ AI applications tested in empirical study
- 1+ academic paper or conference submission
- 1+ vulnerability disclosure (with permission)

### Community Metrics
- 100+ GitHub stars within 6 months
- 5+ external contributors
- Mentioned in 1+ industry publication or blog
- Adopted by 1+ organization

---

## INTERVIEW TALKING POINTS

When discussing this project, emphasize:

- **Solves a real problem** with no good open-source solution
- **Research-backed** methodology aligned with OWASP, NIST, MITRE
- **Production-grade architecture** with multiple SPOF mitigations
- **Multi-model ensemble** for higher accuracy than competitors
- **Privacy-first design** with local-first operation
- **Practicum + portfolio dual purpose** demonstrates academic rigor and practical execution
- **Builds on existing portfolio** — extends ThreatScan and SOCTriage thematically

---

## RESUME ENTRY (Future)

```
PromptShield — Open-Source LLM Vulnerability Scanner
github.com/SalCyberAware/PromptShield | promptshield.vercel.app

- Built the first open-source vulnerability scanner specifically for LLM
  applications, testing AI endpoints and web-based chatbots against OWASP
  LLM Top 10, MITRE ATLAS techniques, and custom adversarial prompts.
- Designed multi-model ensemble analysis engine using Anthropic Claude,
  OpenAI GPT-4o-mini, and local Llama 3 with confidence-weighted voting,
  reducing false positive rate to under 10%.
- Implemented enterprise-grade robustness including local-first operation,
  encrypted credential storage, retry/resume logic, multiple export formats
  (JSON, PDF, HTML, SARIF), and full reproducibility framework.
- Published research paper as MS Cybersecurity practicum at Georgia Tech,
  empirically testing 10+ public AI applications and contributing to OWASP
  LLM Top 10 testing methodology.
- Distributed via PyPI as `pip install promptshield` with full CI/CD pipeline.
```

---

## PRACTICUM ALIGNMENT

This project satisfies CS/ECE/PUBP 6727 Practicum requirements by:

1. **Solving a real-world problem** in a commercial/community setting
2. **Producing measurable impact** (open-source tool used by community)
3. **Contributing original research** to OWASP LLM Top 10 methodology
4. **Demonstrating cybersecurity expertise** across detection engineering, AI security, and tool development
5. **Producing publishable output** suitable for academic or industry venues

---

## RISKS AND MITIGATIONS

### Project Risks

**Risk:** Scope creep makes timeline unrealistic
**Mitigation:** Strict phase-gating, MVP-first approach, defer Phase 2-3 features if needed

**Risk:** AI API costs exceed budget
**Mitigation:** Pattern engine handles obvious cases, local LLM option, scan rate limiting

**Risk:** False positive rate too high to be useful
**Mitigation:** Multi-model ensemble specifically designed for this, manual review workflow

**Risk:** Tool misused for offensive purposes
**Mitigation:** Responsible disclosure documentation, terms of service, ethical use focus

**Risk:** Practicum advisor rejects scope
**Mitigation:** Discuss blueprint early with advisor, build on existing portfolio strength

### Technical Risks

**Risk:** Playwright web scanning detected and blocked by targets
**Mitigation:** Configurable behavior, user agent customization, ethical use only on owned/authorized targets

**Risk:** Attack library becomes outdated
**Mitigation:** Multiple sources, auto-update, community contributions, quarterly review

**Risk:** Compliance/legal issues with scanning third-party tools
**Mitigation:** Clear documentation requiring authorization, no default scanning of public endpoints

---

## NEXT STEPS

1. Discuss blueprint with Georgia Tech practicum advisor
2. Submit Practicum Interest Survey
3. Create GitHub repository: `github.com/SalCyberAware/PromptShield`
4. Set up project structure (Python package skeleton)
5. Begin Phase 1: Initial attack library + CLI scaffolding
6. Establish weekly progress reviews against this blueprint

---

## DOCUMENT VERSION

**Version:** 1.0
**Date:** May 1, 2026
**Status:** Approved design, ready for Phase 1 implementation
