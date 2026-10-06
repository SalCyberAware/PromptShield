# Security Policy

PromptShield is a security tool, and we take its own security posture seriously. This document explains how to report vulnerabilities, our supported versions, and our security commitments.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in PromptShield itself, please report it privately using **GitHub private vulnerability reporting**: open the repository's [Security tab](https://github.com/SalCyberAware/PromptShield/security) and choose **Report a vulnerability**, or go straight to the [new advisory form](https://github.com/SalCyberAware/PromptShield/security/advisories/new). Only the maintainer can see the report. Do not open a public issue, and do not include exploit details in a PR description.

When reporting, please include:

- A clear description of the issue and its impact
- Reproduction steps or a minimal proof of concept
- Affected commit SHA, branch, or release tag
- The exact PromptShield invocation (CLI flags, target type) that triggered it
- Any relevant logs, scanner output, or screenshots

This is a single-maintainer project, so response times are best-effort, not contractual:

- **Initial acknowledgement:** within 5 business days
- **Triage and severity assessment:** within 10 business days of acknowledgement
- **Fix and disclosure:** depends on severity; you'll be kept in the loop, and you'll be credited in the advisory unless you prefer to remain anonymous

If you don't hear back within 5 business days, please ping the advisory thread.

---

## Supported Versions

PromptShield is pre-1.0. Security fixes are applied to the latest release on `main`; older tagged versions are not maintained.

| Version | Supported |
|---------|-----------|
| `main` / latest tagged release (currently 0.6.x) | ✅ |
| Tagged releases prior to the latest | ❌ |

Users should always run the latest release.

---

## In Scope

Because PromptShield is itself a security tool, the scope is more specific than for a typical application. The following are in scope:

### Detection bypass

- **Novel prompt-injection payloads** that evade PromptShield's analyzers (pattern + Claude AI ensemble) with a working **proof of concept** demonstrating the bypass against the current `main`
- **Evasion techniques** that defeat the confidence-weighted voting (e.g., causing both analyzers to mis-classify a malicious payload as clean)

### False-negative reports

- **Known-bad payloads**, particularly those from public sources (cite the paper, OWASP LLM Top 10 entry, MITRE ATLAS technique, or blog post), that PromptShield's attack library or analyzers fail to flag
- Gaps in OWASP LLM Top 10 / MITRE ATLAS coverage where a category is claimed but no working attack exists for it

### Safety issues in the scanner itself

- **Regular-expression denial of service** (catastrophic backtracking) on crafted scanner input or crafted target responses
- **Code injection** via the input parser, attack-library YAML loader, report templates, or CLI argument handling
- **Information disclosure** via error messages: leaking absolute file paths, environment variables, `.env` contents, API keys, or other secrets into terminal output, JSON reports, HTML reports, or stack traces
- **Insecure file handling**: path traversal, arbitrary write, or zip-slip-style issues when reading attacks/data or writing reports
- **TLS / transport issues** in the API scanner (e.g., the User-Agent or auth header leaking via misconfigured retries/redirects)
- **Supply chain issues**: known-exploitable vulnerabilities in the pinned dependencies (`click`, `httpx`, `tenacity`, `anthropic`, `openai`, `playwright`, `jinja2`, `pyyaml`, `cryptography`, etc.) with a working exploit against PromptShield's usage

---

## Out of Scope

- **False positives** (clean prompts flagged as vulnerable). These are detection-accuracy bugs / feature requests, not security issues. Open a regular issue with the prompt and the analyzer that fired.
- **Performance / DoS on local CLI runs** against a target you control. PromptShield is a local CLI; if your scan hangs or spikes CPU on a target you control, that's a performance bug
- **Reports from automated scanners** with no manual validation or proof of exploitability
- **Theoretical issues** without a working exploit against PromptShield's current code
- **Vulnerabilities in the targets PromptShield scans**: those belong with the target's vendor, not here
- **Issues in third-party AI providers** (Anthropic, OpenAI, Ollama, etc.): report those to the provider
- **Issues that require pre-existing privileged access** to the user's machine (root, write access to `site-packages`, etc.)
- **Outdated dependency reports** with no exploit demonstrated against PromptShield's actual code paths

PromptShield also runs as a hosted web demo. Testing against your own clone is always fine and is the preferred way to look for issues. Do not run automated or high-volume testing against the hosted demo: every scan there spends real provider credits. Report demo-specific issues through private vulnerability reporting as described above.

---

## Responsible Use

PromptShield is intended for **defensive security testing of systems you own or have explicit authorization to test**. Misuse of the tool to scan unauthorized targets is prohibited and may violate laws including but not limited to:

- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- General Data Protection Regulation (GDPR) in the European Union
- Equivalent laws in other jurisdictions

By using PromptShield, you agree to:

- Only scan systems you own or have written authorization to test
- Comply with the terms of service of any target API or application
- Respect rate limits and avoid causing denial of service
- Disclose any vulnerabilities you discover responsibly to the affected parties
- Not use PromptShield to harass, harm, or disadvantage any individual or organization

PromptShield's authors and contributors disclaim all liability for misuse of the tool.

---

## Security Commitments

PromptShield is built with the following security principles:

### Where Your Data Goes

PromptShield itself stores nothing. It has no database, does not keep prompts or scan results, does not phone home and does not include telemetry. The CLI writes a report only when you ask for one with `--output`.

Where the prompt and the target's replies travel depends on how you run it:

- **CLI with local analyzers only** (the pattern analyzer, plus Ollama on your own machine if you enable it): the prompt and replies stay on your machine, apart from whatever you send to the target you chose to scan.
- **CLI with cloud analyzers**: the attack, the target's reply and your system prompt are sent to the provider of each cloud analyzer you enable (Anthropic, OpenAI or Google) so it can judge the result. A hosted model used as the target also receives the prompt and attacks.
- **Hosted web demo**: your prompt is sent to OpenAI, which runs the target model, and the prompt and the target's replies are sent to Anthropic and Google, which judge the scan.

Each provider handles that data under its own terms and retention policy. PromptShield has no control over it.

### Credential Handling

API keys and credentials are:

- Not written to terminal output
- Redacted from JSON reports
- Loaded from environment variables or `.env` files (preferred over command-line flags)
- Sent only to the service they belong to: each AI provider's key goes to that provider, and target credentials go to the target you scan

### Local-First Operation

PromptShield works fully offline once the attack library is downloaded. Cloud-based AI analyzers are optional and clearly indicated when used.

### Encrypted Transit

Calls to the hosted AI providers (Anthropic, OpenAI, Google) go over HTTPS through each provider's official SDK, using that SDK's default TLS settings. PromptShield does not yet enforce a minimum TLS version of its own, and it does not refuse plain HTTP. For example, the optional Ollama analyzer talks to a local host over `http://` by default. Refusing plain HTTP targets is not implemented yet.

### Supply Chain

- All dependencies are pinned to specific versions in `pyproject.toml`
- Dependencies are reviewed for known vulnerabilities
- The attack library is version-controlled in this repository. It is not cryptographically signed; signing is not implemented yet.

### Adversarial Resistance

PromptShield includes built-in protections against being weaponized:

- Documentation emphasizes defensive use cases

Not implemented yet: the CLI has no tool-level rate limiting or cap on the number of targets, and responsible disclosure templates are not included (see below).

### API Key Handling

- Anthropic API keys are loaded only from environment variables. They are never committed to the repository: CI runs gitleaks over the full git history, and GitHub push protection is enabled.
- Production uses a dedicated service-account key in its own workspace, with a monthly spend cap.
- Development uses a separate key, also with a spend cap.
- Both keys have an expiry date and are rotated before they expire.
- OpenAI and Google API keys are loaded the same way, from environment variables only. Spend caps and scheduled rotation for those keys are planned but not in place yet.

---

## Disclosure of PromptShield Findings

If you use PromptShield to discover vulnerabilities in third-party AI applications, please follow responsible disclosure:

1. Contact the affected vendor privately first
2. Allow reasonable time for remediation (typically 90 days)
3. Coordinate public disclosure with the vendor
4. Credit the vendor's response when publishing findings
5. Do not exploit findings beyond what's necessary to confirm the vulnerability

PromptShield will provide disclosure templates in a future release.

---

## Compliance Alignment

PromptShield's security architecture aligns with:

- NIST AI Risk Management Framework (AI RMF)
- ISO 42001 (AI Management Systems)
- OWASP LLM Top 10 testing methodology
- MITRE ATLAS adversarial AI taxonomy
- NIST 800-53 (where applicable to security tooling)

---

## Updates to This Policy

This security policy may be updated as PromptShield matures. Material changes will be announced in the project changelog.

Last updated: 2026-10-05
