# Portfolio Automation Plan

**Scope:** PromptShield, ThreatScan, SOCTriage (github.com/SalCyberAware)
**Written:** 2026-09-13
**Status:** Tier 1 is implemented on PromptShield only (`.github/workflows/security.yml`, all jobs
green as of 2026-09-13). Everything else on this page is still a plan.

---

## Why this exists

On 2026-09-11 an audit of SOCTriage found four problems at once:

1. The Railway build had been failing since June. The service was running an old image.
2. The database was on ephemeral storage. Case data was silently lost on every restart.
3. The Vercel project was never connected to git, so the live frontend was serving April's code.
4. The headline feature, the triage submit flow, failed on every click.

The common thread is not that four things broke. Things break. The problem is that all four were
invisible from outside the system. The README badges were green. The repo was clean. Nothing in the
toolchain was watching the part that actually matters, which is whether the deployed thing works.

All four have since been fixed, two in the repo and two in platform configuration.

- **The broken feature** was fixed by `5b2693d` (2026-09-12), which realigned the SOCTriage frontend
  with the API contract and wired the health check.
- **The Vercel disconnect** is resolved. The project is git-connected to `main` and auto-deploying,
  verified by a push triggering a build within 30 seconds. Commit `b966dbf` (2026-09-12) was that
  triggering push.
- **The ephemeral database** is resolved. A Postgres service is attached on Railway with
  `DATABASE_URL` set, verified by `created_at` returning with a `Z` suffix, which is Postgres
  behavior rather than SQLite.
- **The Railway build failure** is fixed. The cause was a mise attestation failure on the pinned
  Python version, worked around by setting `MISE_PYTHON_GITHUB_ATTESTATIONS=false`. That is a
  workaround, not a fix, and is recorded as technical debt below.

Fixing all four does not make the plan less necessary. It took a manual audit to find them, and the
same audit would find nothing today. The question this document answers is what would have found
them without the audit.

This plan exists so that this class of failure gets caught by a machine on a schedule instead of by
a human who happened to click the demo link.

---

## Principle

**Automation detects and proposes. A human approves anything that changes code or production.**

The split is not about trust in the tooling. It is about where a wrong decision costs something. A
scanner that reports a false positive costs a few minutes of reading. A bot that merges a bad
dependency bump into a running service costs an outage that nobody notices for three months.

**Auto-merge-safe (no human in the loop):**

- Running a scanner and writing its output to a check, a log, or an alert.
- Opening an issue or a PR that a human will read.
- Pinging a health endpoint and comparing the response to what was expected.
- Posting a notification to an alert channel.

In other words: anything that only ever produces *information*. If the worst case of a bad run is a
noisy message, it does not need approval.

**Always requires human review (never auto-merge):**

- Any commit to a default branch, including dependency bumps that pass CI.
- Any change to a deploy pipeline, a build command, or a platform setting.
- Any change to secrets, environment variables, or their names.
- Any change to authentication, database schema, or migration files.
- Any change to PromptShield's honesty and verdict logic (see Tier 3).

There is no auto-merge anywhere in this plan, including for patch-level dependency updates. Three
small repos do not generate enough dependency traffic to justify the risk, and the whole point of
the audit was that unattended automation is what produced a silent failure.

---

## Tier 1: fully automated, no approval needed

These only report. They never modify a file and never touch production. They can be added, changed,
and removed without ceremony.

### 1.1 Vulnerability scanning

- **Python repos (PromptShield, SOCTriage):** `pip-audit` as a CI job on push and pull request, plus
  a weekly scheduled run so a newly disclosed CVE in an unchanged dependency still surfaces.
- **Node repos (ThreatScan, plus the frontends of the other two):** `npm audit --audit-level=high`
  on the same triggers.
- Scheduled runs that find something open an issue. PR runs fail the check and report inline.
- Start non-blocking for the first two weeks to measure the real noise level, then make it blocking
  at `high` and above.

### 1.2 Secret scanning

- `gitleaks` as a CI job on every push and pull request, across all three repos.
- Full-history scan once at adoption, then incremental on each run.
- This is worth doing carefully. All three repos handle third-party API keys, and ThreatScan alone
  fans out to eleven external intel providers, each with its own key.
- A gitleaks hit is the one Tier 1 result that should page rather than queue.

### 1.3 Static analysis

- GitHub CodeQL, default setup, on `python` for PromptShield and SOCTriage and
  `javascript-typescript` for ThreatScan and the frontends.
- Weekly schedule plus on pull request.
- Results land in the Security tab. Triage weekly. Do not gate merges on CodeQL until the backlog is
  at zero, or the first noisy week will train everyone to ignore it.

### 1.4 Uptime and health monitoring

This is the highest-value item in the whole plan, because it is the one that would have caught the
September failure on the day it happened rather than three months later.

- An external monitor hitting each service's health endpoint on a fixed interval (five minutes is
  fine) and alerting on failure.
- Endpoints that exist today, confirmed in the code:
  - PromptShield backend: `GET /api/health` (`backend/main.py:93`)
  - ThreatScan backend: `GET /api/health` (`backend/server.js:147`)
  - SOCTriage backend: `GET /health` (`backend/main.py:41`)
- Frontends need a check too, and a plain "does the page return 200" check is not enough. A stale
  Vercel build returns 200 happily. See the deploy verification section for what the frontend check
  has to assert instead.
- Alerts go somewhere that gets read. An alert nobody sees is the same as no alert.

### 1.5 Implementation status

**PromptShield: 1.1, 1.2 and 1.3 are live** in `.github/workflows/security.yml` as of 2026-09-13.
Five jobs, all green on first run, alongside the seven existing `ci.yml` jobs which were not touched.
**1.4 (uptime monitoring) is not done**, and it remains the highest-value item on this page.

ThreatScan and SOCTriage have none of Tier 1 yet.

Two deliberate deviations from what 1.1 specifies above, both made because the measured noise level
turned out to be zero:

- `npm audit` went in blocking at `high` immediately rather than non-blocking for two weeks. The
  two-week soak existed to measure noise before committing; the frontend production tree has no
  findings at all, so there was nothing to measure.
- Scheduled runs fail the job rather than opening an issue. A failed scheduled run is already
  visible and already emails the owner. Issue-opening can be added if weekly failures start getting
  scrolled past.

**Findings on the existing code, recorded so they are not lost:**

- pip-audit: clean on both Python trees (45 packages resolved from the root package).
- npm audit: clean on the frontend production tree. The full tree including dev carries 6 findings
  (5 high, 1 moderate), all transitive build-toolchain advisories, excluded by `--omit=dev` for the
  reasons commented on the job.
- gitleaks: clean across all 108 commits of history.
- **CodeQL: 2 open high-severity alerts**, both `py/incomplete-url-substring-sanitization` in
  `promptshield/engines/api_scanner.py` at lines 61 and 63, in `detect_provider`. They are open and
  unsuppressed pending a decision. See the open findings section below.

---

## Tier 2: automated proposal, human merges

### Dependency updates

One of Dependabot or Renovate, configured per repo. Renovate is the better fit here because its
grouping is more expressive and all three repos have a backend and a frontend with separate
lockfiles, but Dependabot is native to GitHub and needs no app install. Either is acceptable. Pick
one and use it for all three so there is one mental model, not two.

**Grouping.** The goal is few PRs that are each easy to judge, not one PR per package.

- Group all non-major backend dependencies into one weekly PR per repo.
- Group all non-major frontend dependencies into one weekly PR per repo.
- Group GitHub Actions version bumps into a single monthly PR per repo.
- Major version bumps get their own PR, one per package, always. A major bump is a reading task, not
  a rubber stamp.
- Security advisories bypass the schedule and open immediately.

**Gate.** CI must pass before the PR is considered mergeable. For the repos where CI does not yet
cover the deployed surface (SOCTriage has no frontend job at all today), the dependency bot should
not be turned on for that surface until the CI job exists. A green check that tests nothing is worse
than no check, because it manufactures confidence.

**Merge is manual, every time.** No auto-merge rules, including for patch updates.

---

## Tier 3: always manual, no automation proposes changes here

Automation may *report* on these areas. It may never open a PR that changes them.

- **Authentication.** Anything that adds, removes, or alters an auth check.
- **Secrets.** Key names, key rotation, environment variable wiring, `.env.example` contents.
- **Database schema.** SOCTriage's SQLAlchemy models and any migration. A schema change that goes
  out unreviewed against a production database is not recoverable by reverting the commit.
- **Production configuration.** `railway.json`, `Procfile`, `runtime.txt`, Vercel project settings,
  CORS origins, build commands.
- **Deploy pipelines.** The workflows themselves, and anything that changes when or how a deploy fires.
- **PromptShield's honesty and verdict logic.** Specifically `backend/scan.py` and
  `promptshield/models.py`: the per-attack status values, `_FINDING_STATUSES`, `_EXCERPT_STATUSES`,
  `_VERDICT_ERROR_FLOOR`, and the analyzer cascade ordering. This code decides what the product
  claims is true. The distinction between "an attack got through", "this needs review", and "the
  judge errored and we are not counting it" is the product's entire credibility. A dependency bump
  that quietly changes a model's output format, or a refactor that collapses `not_ai_judged` into
  `blocked`, turns an honest tool into one that overstates its results. That failure is invisible in
  a diff review unless a human is specifically looking for it, which is why it also needs the eval
  harness described in the gaps section.

---

## Deploy verification

**The rule: after every deploy, confirm the new build actually shipped. Do not assume.**

A deploy that reports success and a deploy that produced a working service are different events.
The SOCTriage Vercel failure is the exact case this catches. The project was disconnected from git,
so pushes to main produced no deploy at all. Every signal a developer would normally look at was
green: CI passed, the repo was clean, the site was up and returning 200. It was just serving code
from April.

A post-deploy verification step catches that on the first push after it starts happening, because it
asks a question a stale build cannot answer correctly.

**What the check does, for each service:**

1. Read the commit SHA that was just pushed.
2. Hit the deployed service and ask it what it is running.
3. Compare. If they do not match, fail loudly.
4. Separately, hit the health endpoint and assert the response body, not just the status code.
5. Hit one real functional endpoint, not just health, and assert the response shape.

**What this requires that does not exist yet:**

- Each backend needs to expose its build identity. The health endpoints today return a hardcoded
  version string (SOCTriage returns `"version": "1.0.0"`, set literally in `backend/main.py`), which
  cannot distinguish today's build from April's. Each health response needs to include the actual
  commit SHA, injected at build time from the platform's git environment variable.
- Each frontend needs the same: a build-time-injected SHA, exposed somewhere the check can read it,
  such as a meta tag or a small `/version.json` emitted by the build.

That is a code change in all three repos and is therefore out of scope for this document, but it is
a prerequisite for step 3 and is sequenced accordingly in the rollout.

Until the SHA plumbing exists, a weaker interim check is still worth having: assert that the health
endpoint responds and that one real endpoint returns a correctly shaped response. That would have
caught failure 4 (the broken triage submit) even though it would have missed failure 3 (the stale
build).

---

## Per-repo current state

Read from the repos on 2026-09-13. Rows marked "platform-verified" were confirmed on Railway and
Vercel rather than in the repo. Anything that was neither read from the repo nor checked on the
platform is marked unverified. ThreatScan's deploy state is the one gap: it was not checked.

| | PromptShield | ThreatScan | SOCTriage |
|---|---|---|---|
| **Workflow files** | `.github/workflows/ci.yml`, `.github/workflows/security.yml` | `.github/workflows/ci.yml` | `.github/workflows/backend-tests.yml` |
| **CI jobs** | 12 across two workflows. `ci.yml` has 7: test (Python 3.11/3.12/3.13 matrix), lint (ruff), typecheck (mypy strict), backend (clean prod install + pytest), frontend (eslint + vite build + vitest). `security.yml` has 5: pip-audit, npm audit, gitleaks, CodeQL (python), CodeQL (javascript-typescript) | 2: backend (jest with coverage, `node --check server.js`), frontend (eslint + vite build + vitest) | 1: pytest with coverage |
| **Backend tests** | 239 test functions in `tests/`, 62 in `backend/tests/` | 229 `it()` blocks across 13 jest files | 62 test functions across 4 files |
| **Frontend tests** | Yes. 2 vitest files, added 2026-09-04 (`78ce0b5`) | Yes. 4 vitest files, added 2026-09-11 (`f6a5925`) | **None.** No test script in `frontend/package.json`, no frontend CI job |
| **Lint in CI** | Yes, both sides (ruff + eslint) | Frontend only. No backend linter | **No.** `eslint` is in `frontend/package.json` but never runs in CI |
| **Type checking** | Yes, mypy strict on `promptshield/` | No | No |
| **Coverage reporting** | Codecov, from the 3.13 matrix leg | Codecov, backend only | Codecov, backend only |
| **Deploy config in repo** | `railway.json` (backend), `backend/Procfile`, `backend/runtime.txt` | None in repo. README documents manual Railway and Vercel setup | `backend/Procfile`, `backend/runtime.txt`. No `railway.json` |
| **Deploy git-connected** | Yes, both. Railway and Vercel are git-connected and deploying (platform-verified) | Unverified. Not determinable from the repo, and not checked on the platform | Yes, both. Vercel is git-connected to `main` and auto-deploying, verified by a push triggering a build within 30 seconds. It was disconnected as of the 2026-09-11 audit |
| **Railway build health** | Building and deploying (platform-verified) | Unverified | Fixed. Was failing since June on a mise attestation failure for the pinned Python version, worked around with `MISE_PYTHON_GITHUB_ATTESTATIONS=false`. See the technical debt section |
| **Database** | None | None | Postgres on Railway, attached with `DATABASE_URL` set (platform-verified: `created_at` returns with a `Z` suffix). `backend/database.py` still falls back to `sqlite:///./soctriage.db` when `DATABASE_URL` is unset, which is correct for local development but was the ephemeral-storage bug in production |
| **Monitoring** | **None.** No uptime check, no alerting, no error tracking found | **None** | **None** |
| **Dependency bot** | **None.** No `dependabot.yml` or `renovate.json` | **None** | **None** |
| **Secret scanning** | Yes. gitleaks over the full git history on push, pull request, and weekly. Pinned release, checksum-verified, `--redact` so findings are not republished into a public Actions log | **None** | **None** |
| **Vulnerability scanning** | Yes. pip-audit over both Python trees (root package and `backend/requirements.txt`) and `npm audit --omit=dev` over the frontend production tree, on push, pull request, and weekly | **None** | **None** |
| **CodeQL** | Yes. `python` and `javascript-typescript`, on push, pull request, and weekly. Alerts go to the Security tab and do not fail the workflow | **None** | **None** |

Notes on the table:

- Test counts come from counting test function definitions and `it()` blocks in the source. The
  actual number of collected cases will be higher wherever parametrization is used. SOCTriage's
  README claims a "71-test pytest suite"; the repo has 62 `def test_` definitions, and the
  difference is consistent with parametrized cases. Neither number was verified by running the suite.
- Coverage percentages are not listed. All three upload to Codecov, but the current percentage is a
  property of the Codecov project, not the repo, and is unverified here.
- "Monitoring: none" was established by searching all three repos for references to uptime and
  error-tracking services and finding no configuration of any kind.

---

## Technical debt: the mise attestation workaround

**Where:** SOCTriage, Railway build environment. `MISE_PYTHON_GITHUB_ATTESTATIONS=false`.

The Railway build that had been failing since June was failing because mise could not verify the
GitHub build attestations for the pinned Python version (`python-3.11.9`, in `backend/runtime.txt`).
The build now succeeds because that verification is switched off.

**What that costs.** Attestation checking is a supply-chain control. It confirms the Python
toolchain the builder downloads was produced by the build pipeline it claims to come from, and not
substituted somewhere between publication and the build host. Disabling it does not make a
compromise likely, but it does remove the check that would notice one. It is worth naming plainly
that a security portfolio is currently building one of its three services with a supply-chain
verification step turned off.

**Why it is acceptable for now.** The alternative was a service that did not build at all, and had
not built for three months. Shipping with the check disabled and a note is better than the state
this replaced.

**The proper fix.** Resolve to a Python version whose attestations the builder can verify, and
remove the variable. That most likely means moving off the exact pinned patch version to one mise
can verify cleanly, and keeping `backend/runtime.txt` and the CI matrix in step with whatever that
turns out to be (`.github/workflows/backend-tests.yml` pins `3.11.9` with a comment saying to keep
it in sync with `runtime.txt`, so both move together). Worth attempting whenever SOCTriage's Python
version is next touched, rather than scheduling a dedicated session for it.

**Do not let it go quiet.** This is exactly the kind of thing that is invisible from outside, which
is the failure mode this whole document exists to address. The variable lives in Railway's
environment, where nothing in the repo will remind anyone it is set. Removing it should be a
checklist item on the next SOCTriage dependency or runtime change.

---

## Open findings: CodeQL on `detect_provider`

CodeQL's first run opened two high-severity alerts, both
`py/incomplete-url-substring-sanitization`, at `promptshield/engines/api_scanner.py:61` and `:63`.
Both are in `detect_provider`, which picks a request format from the target URL:

```python
if "anthropic.com" in url_lower or "/v1/messages" in url_lower:
    return APIProvider.ANTHROPIC
if "openai.com" in url_lower or "/chat/completions" in url_lower:
    return APIProvider.OPENAI
```

**The rule is correct about the code.** A substring test is not a host test. `anthropic.com` matches
`https://anthropic.com.example.net/`, and it matches `https://example.net/?ref=anthropic.com`. If
this check were an allowlist, that would be a straightforward bypass.

**The severity is lower here than the label suggests**, for two reasons worth stating rather than
assuming. First, the URL is supplied by the operator: it is the endpoint they asked PromptShield to
scan, not attacker-controlled input arriving over the network. Second, the return value selects a
payload format, not a trust decision. A wrong answer produces a malformed request and a failed
scan, not an escalation. The API key travels to the target URL regardless of which branch is taken,
including the `CUSTOM` fallback, so the detection is not what puts the credential on the wire.

**They are open and unsuppressed.** No dismissal, no inline `nosec`, no query filter. The fix is
cheap and correct: parse the URL and compare the host, matching exactly or on a dot-boundary suffix,
instead of testing a substring of the whole URL. That makes the detection right as well as safe, and
it removes a genuine footgun if this function is ever reused somewhere the URL is less trusted.

Fixing it is a code change and therefore not part of the Tier 1 commit, which only added reporting.
It is a small, self-contained change waiting on a decision.

---

## Enterprise gaps, honestly stated

These are real gaps. None is done, and none is scheduled by this document. They are listed because a
plan that only describes what is easy is not a plan.

### Authentication: absent everywhere

**No backend in any of the three repos has authentication.** Not PromptShield, not ThreatScan, not
SOCTriage. There is no `Depends()`, no API key header, no bearer token, and no session anywhere in
the application code of any of them. Every endpoint is open to any caller who knows the URL.

The exposure is not the same in all three, and the difference is worth stating precisely.

**PromptShield and ThreatScan: API budget spend.** Both backends call paid third-party APIs on
behalf of anonymous callers. PromptShield runs a full attack scan against a real model per request,
and ThreatScan fans out to eleven intel providers. An unauthenticated caller cannot read anything
they should not, because neither service stores user-submitted data across requests, but they can
spend the owner's API budget at whatever rate the rate limiter allows. The in-memory rate limiters
described below are the only thing standing between a scripted caller and the bill.

**SOCTriage: API budget spend, plus stored case data.** SOCTriage has the same exposure, and on top
of it, it persists what users submit and exposes that data through unauthenticated endpoints:

- `GET /health`
- `POST /api/triage`
- `GET /api/cases`
- `GET /api/cases/{case_id}`
- `GET /api/dashboard`

`GET /api/cases` returns every case in the database to any caller. `POST /api/triage` writes to it.
So an anonymous caller can read the stored case data and add to it. Now that Postgres is attached
and the data actually survives restarts, this matters more than it did in September, not less: the
ephemeral storage bug was destroying the same data that has no access control on it.

For a public portfolio demo, open access is a defensible tradeoff, since the point is that a visitor
can click the link and see it work. It is worth being explicit that it *is* a tradeoff rather than an
oversight, and that SOCTriage is where the tradeoff is most expensive.

### Multi-tenancy: not designed for it

Every rate limiter in the portfolio is in-memory and single-instance:

- PromptShield's `backend/limits.py` holds per-IP and daily-cap state in process memory. The comment
  at `backend/main.py:34` says so directly: "Single shared limiter for this instance. In-memory state."
- ThreatScan uses `express-rate-limit` with its default in-process store (`backend/server.js:135`
  and `:141`).
- SOCTriage has no rate limiting at all.

The consequence is that the moment any of these scales past one instance, the limits become
per-instance rather than per-user, and the effective limit multiplies by the instance count. There
is also no tenant concept anywhere: no user IDs, no org IDs, no row-level ownership on SOCTriage's
cases. Fixing this is not a configuration change. It is a data model change plus a shared store such
as Redis.

### Audit logging: none in any repo

No audit trail exists in any of the three repos. A search for audit logging across all application
code returns nothing. For SOCTriage specifically this means there is no record of who triaged what,
when a case changed, or what the AI returned at the time the decision was made. For a tool whose
subject matter is security operations, that is the most conspicuous gap on this list.

### Eval harness for verdict regression: does not exist

There is no eval harness in any repo. This is the missing safety net under Tier 3's honesty rule.

PromptShield's value is that its verdicts are honest: it distinguishes an attack that got through
from one that needs review from one where the judge errored and is therefore not counted. That
distinction lives in `backend/scan.py` and depends on the behavior of external models that change
underneath the code without any commit to this repo.

The existing unit tests check that the code handles a given analyzer response correctly. They cannot
check that the analyzers still produce the responses the code was written for. A harness that runs a
fixed set of known-vulnerable and known-safe prompts through the real cascade and asserts the
expected verdict distribution would catch model drift, prompt regressions, and cascade misordering.
Nothing else in the current toolchain can.

This is the item most worth building and the one furthest from being started.

---

## Rollout order

The sequence answers one question: what is the cheapest thing that would have caught the September
failure? Everything that closes the visibility gap comes before everything that improves code
quality, because the audit did not find a code quality problem. It found a blindness problem.

**Step 1. External uptime and health monitoring on all six deployed surfaces.**
First because it is the only item that catches a live outage today, with no code change and no CI
change. Three backends, three frontends, five-minute interval, alerts routed somewhere a human
reads. This is an afternoon of work and it closes the largest hole.

**Step 2. Secret scanning (gitleaks) across all three repos.**
Second because it is the highest-severity thing that could already be wrong with nobody knowing.
Unlike the other scanners, a finding here is an emergency rather than a backlog item, and the
full-history scan either finds something or permanently retires the worry.

**Step 3. Build identity in every health response, then post-deploy verification.**
Third because it needs a code change in all three repos (the commit SHA plumbing) and is therefore
slower than steps 1 and 2, but it is the step that specifically closes the stale-build failure mode.
Once a health response reports the SHA it is running, a five-line check after every deploy makes a
disconnected Vercel project impossible to miss.

**Step 4. Bring SOCTriage's CI up to the level of the other two.**
Fourth because SOCTriage is where all four audit findings landed, and it has the weakest CI of the
three: one job, backend only, no lint, no type checking, no frontend tests at all. The headline
feature that was failing on every click was a frontend and API contract problem, which is exactly
the surface with zero automated coverage. This is also a prerequisite for step 6, since turning on a
dependency bot for an untested surface manufactures false confidence.

**Step 5. Vulnerability scanning and CodeQL.**
Fifth because these produce backlogs rather than alerts. They are valuable, but a finding here is
something to schedule, not something to wake up for, and adding them before steps 1 to 4 would mean
spending the first week triaging static analysis output while the deployed services stay unwatched.

**Step 6. Dependency update PRs.**
Sixth, and deliberately last among the automation items, because it is the only one that proposes
changes to code. It should not be switched on until CI is trustworthy enough that a green check on a
dependency PR actually means something, which is what steps 4 and 5 establish.

**Then, separately: the eval harness.**
Not numbered with the rest because it is a build, not a configuration. It is the largest item on
this page and the one with the least precedent to copy from. Start it once the six steps above are
running and the portfolio is no longer blind, and treat it as its own project rather than a task.

The authentication, multi-tenancy, and audit logging gaps are not in this sequence at all. Each is a
product decision with a data model behind it, and none belongs in a document about automated
maintenance. They are recorded above so that the list of what is not done stays honest.
