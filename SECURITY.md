# Security Policy

PromptShield is a security tool, and we take its own security posture seriously. This document explains how to report vulnerabilities, our supported versions, and our security commitments.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in PromptShield itself, please report it privately via one of these channels:

- **Email:** Sal127@proton.me
- **GitHub Security Advisory:** Use GitHub's private vulnerability reporting feature on the [PromptShield repository](https://github.com/SalCyberAware/PromptShield/security/advisories/new)

When reporting, please include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix if known

We commit to:

- Acknowledging your report within 72 hours
- Providing an initial assessment within 7 days
- Keeping you informed of remediation progress
- Crediting you in the fix advisory unless you prefer to remain anonymous

---

## Supported Versions

PromptShield is in active early development. Security fixes are applied to the latest released version on the main branch.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Older alpha versions are not supported. Users should always run the latest version.

---

## Scope

The following are in scope for vulnerability reports:

**In scope:**

- Vulnerabilities in PromptShield's own code (CLI, scanner engine, analyzers, reporters)
- Issues that could leak user secrets (API keys, scan data)
- Authentication bypass or privilege escalation in PromptShield
- Vulnerabilities in PromptShield's dependencies that affect users
- Issues that could cause PromptShield to behave unsafely against unintended targets

**Out of scope:**

- Vulnerabilities in the targets PromptShield scans (those should be reported to the target's vendor)
- Issues in third-party AI providers (Anthropic, OpenAI, etc.) — report those to the provider
- Theoretical attacks without a clear exploitation path
- Issues that require physical access to the user's machine

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

### Zero Data Retention by Default

Scans are not transmitted, logged, or stored anywhere unless the user explicitly enables logging or saves output. PromptShield does not phone home and does not include telemetry.

### Secret Handling

API keys and credentials are:

- Never logged or written to terminal output
- Automatically redacted from JSON reports
- Loaded from environment variables or `.env` files (preferred over command-line flags)
- Never transmitted to any third party except the user-specified target

### Local-First Operation

PromptShield works fully offline once the attack library is downloaded. Cloud-based AI analyzers are optional and clearly indicated when used.

### Encrypted Transit

All API calls use TLS 1.3 minimum. PromptShield will refuse to scan targets over plain HTTP unless explicitly overridden.

### Supply Chain

- All dependencies are pinned to specific versions in `pyproject.toml`
- Dependencies are reviewed for known vulnerabilities
- The attack library is signed and version-controlled

### Adversarial Resistance

PromptShield includes built-in protections against being weaponized:

- Tool-level rate limiting prevents bulk-scanning thousands of targets
- Documentation emphasizes defensive use cases
- Responsible disclosure templates are included

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

Last updated: May 2026
