# Contributing to PromptShield

Thanks for considering a contribution. PromptShield is an open-source vulnerability scanner for LLM applications, and the project benefits from input from security researchers, developers, and AI/ML practitioners.

This document explains how to get involved.

---

## Ways to Contribute

There are several ways to help, and all are valuable:

- **Report bugs** by opening an issue with reproduction steps
- **Suggest features** by opening an issue describing the problem you'd like solved
- **Contribute new attacks** to the attack library (high impact, low barrier to entry)
- **Improve detection accuracy** by tuning expected indicators or false positive patterns
- **Write documentation** — usage examples, deep dives, troubleshooting guides
- **Submit code** for new analyzers, scanners, reporters, or fixes
- **Share findings** if you discover vulnerabilities in public AI applications (responsibly)

---

## Code of Conduct

PromptShield follows a straightforward principle: be respectful, constructive, and focused on improving the project. Personal attacks, harassment, or hostile behavior will not be tolerated. Discussions should center on technical merit and security outcomes.

If you observe behavior that violates this principle, contact the maintainer privately.

---

## Reporting Bugs

Before opening a bug report, please:

1. Search existing issues to confirm the bug hasn't already been reported
2. Verify the issue exists on the latest main branch
3. Collect reproduction information (Python version, OS, full error output)

When opening the issue, include:

- Clear, descriptive title
- Steps to reproduce
- Expected behavior vs actual behavior
- Environment details (OS, Python version, PromptShield version)
- Sanitized scan output if relevant — never include API keys

---

## Contributing New Attacks

New attacks are the most valuable community contribution. Each attack should map to a specific OWASP LLM Top 10 category, MITRE ATLAS technique, or be novel enough to warrant a CUSTOM classification.

**Attack contribution checklist:**

- The attack tests a real vulnerability class, not a one-off prompt
- Expected indicators are specific enough to detect success but general enough to not over-trigger
- False positive patterns capture common refusal/safety phrases
- Severity rating reflects realistic impact
- Remediation guidance is actionable
- References cite the original source (paper, blog post, OWASP, MITRE)

To add an attack:

1. Edit `promptshield/attacks/data/attacks_v1.yaml`
2. Follow the existing schema
3. Use ID format `PS-<CATEGORY>-<3-digit-number>` (next available number)
4. Run `promptshield library show <YOUR_ID>` to verify it loads correctly
5. Open a pull request with a clear description of what the attack tests

---

## Code Contributions

### Setup

```bash
git clone https://github.com/SalCyberAware/PromptShield.git
cd PromptShield

python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

pip install -e ".[dev]"
```

The `[dev]` extra pulls in `pytest`, `pytest-asyncio`, `pytest-cov`, `black`, `ruff`, and `mypy`. After install the CLI is on your `PATH` as `promptshield`:

```bash
promptshield --help
promptshield library list                     # browse the attack library
promptshield scan https://your-endpoint ...   # run a scan
```

### Development Standards

- **Python version:** 3.11+ (CI runs the matrix on 3.11, 3.12, and 3.13)
- **Style:** Black formatting, Ruff linting (`ruff` is gated in CI — see `pyproject.toml` for the rule set and per-file ignores)
- **Type hints:** Required on all new functions and methods (mypy runs in **strict mode** on every push)
- **Docstrings:** Required on public functions, classes, and modules
- **Tests:** Required for new features (we use pytest with `pytest-asyncio` and `pytest-cov`)

### Running Tests

```bash
pytest tests/ -v                                                # what CI runs
pytest tests/ --cov=promptshield --cov-report=term-missing      # with coverage
```

CI uploads `coverage.xml` to Codecov on the 3.13 matrix entry; the badge in the README links to the live report. Coverage at the time of v0.3.0 is around **93%**.

### Linting and Type Checking

```bash
ruff check promptshield/ tests/    # lint (CI uses --output-format=github)
mypy promptshield/                 # strict-mode type check
```

Both must pass on every push — the CI pipeline has three independent jobs (`test`, `lint`, `typecheck`) and all three gate `main`.

### Pull Request Process

1. Fork the repository and create a feature branch (`git checkout -b feature/your-feature-name`)
2. Make your changes following the development standards above
3. Add or update tests as needed — keep coverage at or above the current level
4. Update relevant documentation (README, docs/, docstrings)
5. Ensure all three checks pass locally:
   - `pytest tests/ -v`
   - `ruff check promptshield/ tests/`
   - `mypy promptshield/`
6. Commit using [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): description`. Types in active use: `feat`, `fix`, `test`, `docs`, `refactor`, `ci`, `chore`, `style`.

   Recent examples from `git log`:

   ```
   feat(engines): add tenacity retry/backoff to API scanner
   test(cli): add 25 tests for Click CLI using CliRunner
   style(types): enable mypy strict mode (16 annotation fixes)
   ci: fail the run when ruff finds issues
   ```

7. Push to your fork and open a pull request against `main`
8. Respond to review feedback — the three CI jobs (`test`, `lint`, `typecheck`) must be green before merge

PRs should be focused — one logical change per PR. If you're tackling something large, open an issue first to discuss the approach.

---

## Documentation Contributions

Documentation improvements are always welcome. The documentation lives in:

- `README.md` — high-level overview
- `docs/` — in-depth guides
- Docstrings in code

When updating documentation:

- Use clear, simple language
- Include examples where useful
- Test any commands or code snippets you include
- Be specific — vague guidance helps no one

---

## Security Issues

**Do not open public issues for security vulnerabilities.** Instead, follow the disclosure process in [SECURITY.md](SECURITY.md).

---

## Questions

If you're unsure whether to contribute something, open an issue and ask. It's much better to discuss a change before investing time than to have a PR rejected.

---

## Recognition

All contributors are credited in release notes. Significant contributions may be acknowledged in the README contributors section. PromptShield is a community-driven project — your work matters.

Thank you for helping make AI applications more secure.
