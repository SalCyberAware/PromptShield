# Portfolio Automation Plan

**Scope:** PromptShield, ThreatScan, SOCTriage (github.com/SalCyberAware)
**Written:** 2026-09-13
**Status:** Tier 1 is implemented across all three repos as of 2026-09-16, and every scanner job is
green. Each repo has its own `security.yml`; the uptime monitor for all six deployed surfaces runs
from PromptShield's `uptime.yml`. Every advisory the scanners found on first run has been fixed.
**Deploy verification is live on all six surfaces as of 2026-09-18:** every backend reports the
commit SHA it is running and every frontend bakes its into the served HTML, and each repo has a
`deploy-verify.yml` that polls both of its own surfaces after every push to `main` until each
reports that commit. Tiers 2 and 3 and the enterprise gaps are still plans.

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

**1.1, 1.2 and 1.3 are live for PromptShield** in `.github/workflows/security.yml` as of
2026-09-13. Five jobs, all green on first run, alongside the seven existing `ci.yml` jobs, which
were not touched.

**ThreatScan has 1.1, 1.2 and 1.3 as of 2026-09-16**, in its own
`.github/workflows/security.yml`, adapted rather than copied: no pip-audit job because there is no
Python, two npm audit jobs because a server tree and a browser tree are different risks, and CodeQL
on `javascript-typescript` only.

**SOCTriage has 1.1, 1.2 and 1.3 as of 2026-09-16**, in its own
`.github/workflows/security.yml`. One Python tree rather than PromptShield's two, since there is no
installable root package here, pinned to Python 3.11.9 to match `backend/runtime.txt` so the tree
resolves the way production does. **Tier 1 now covers all three repos.**

**1.4 is live for all three projects** in `.github/workflows/uptime.yml` as of 2026-09-14. Six
checks on a 15 minute schedule plus manual dispatch: a backend health endpoint and a frontend for
each project. Each service is its own step, so a red run names what is down, and every step runs
even after an earlier one fails so one outage cannot hide the next. Read-only and unauthenticated;
no secrets. It lives in PromptShield because that is where this plan lives, and it watches the other
two repos from here rather than each carrying a copy.

**What the 15 minute interval does and does not buy.** This repository is public, so Actions minutes
are unmetered and the interval costs nothing. Two limits are worth knowing rather than discovering
later:

- GitHub disables scheduled workflows in a public repository after 60 days with no repository
  activity. A monitor that quietly stops after two idle months is exactly the failure this plan
  exists to prevent, so treat a long quiet spell as a reason to check that the schedule still runs.
- Scheduled runs are best-effort and get delayed under load, so detection is on the order of tens of
  minutes. This catches a sustained outage, a bad deploy, and a service that fails to restart. It
  will not catch a brief blip, and it is not a substitute for a dedicated uptime service if
  minute-level detection ever matters.

Were this repository private, the same interval would cost roughly 2,880 billed minutes a month
against a 2,000 minute free allowance. A 30 minute interval would fit inside it.

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
- **CodeQL: 2 high-severity alerts**, both `py/incomplete-url-substring-sanitization` in
  `promptshield/engines/api_scanner.py` at lines 61 and 63, in `detect_provider`. Fixed in `72dfb57`
  and closed by CodeQL on 2026-09-14. See the resolved findings section below.

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

**Backend build identity: DONE 2026-09-17.**

All three health responses now carry a `commit` field alongside the fields they already had. The
value is read from `RAILWAY_GIT_COMMIT_SHA`, which Railway sets on every deployment that originates
from a GitHub push and exposes to the running container, with `GIT_COMMIT_SHA` as a platform-neutral
override and `"unknown"` when neither is set so local development is unaffected. Verified live on
all three services on 2026-09-17: each reported the exact SHA of the commit that had just been
pushed. The hardcoded `"version"` strings were left in place, so nothing that already read them
broke.

**Backend post-deploy verification: DONE 2026-09-17.**

Each repo carries its own `.github/workflows/deploy-verify.yml`, triggered on push to `main`. It
polls that repo's backend health endpoint every 15 seconds for up to 15 minutes, and passes only
when the reported commit matches `github.sha` (an abbreviated SHA that prefixes the full one counts)
*and* the body still says `"status": "ok"`. On timeout it distinguishes three diagnoses, because
they have different fixes: no `commit` field or no response at all, `"unknown"` (the platform
variable is not reaching the container), and a different SHA (the stale-build case this exists to
catch). `uptime.yml` additionally asserts that each backend's `commit` looks like a SHA, so a
backend that quietly loses its build identity between deploys is caught within 15 minutes rather
than at the next push.

The check lives in each repo rather than centrally with `uptime.yml`, because a workflow can only
subscribe to its own repository's push events. Watching the other two from here would need a
cross-repo `repository_dispatch` and a personal access token in all three, which is more standing
credential than a deploy check is worth.

**Frontend build identity: DONE 2026-09-18.**

A frontend cannot report a SHA from a request handler, because there is no handler: the deployed
artifact is a directory of static files. The equivalent is to bake the SHA into the artifact at
build time. All three frontends now do, through a small Vite plugin that injects
`<meta name="build-commit" content="...">` into `index.html` from `VERCEL_GIT_COMMIT_SHA`, with
`GIT_COMMIT_SHA` as a platform-neutral override and `"unknown"` when neither is set.

The meta tag rather than a `/version.json` on purpose: `index.html` is the document whose staleness
*is* the failure, because it names the content-hashed asset bundles. A `version.json` is a separate
file that can be served fresh while `index.html` is stale, which would let the check pass on a stale
site — the precise thing it exists to prevent.

**This requires "Enable access to System Environment Variables" to be ticked in each Vercel
project's settings.** Without it the build sees no SHA and the page reports `"unknown"`, which the
check reports as a platform configuration problem rather than a stale build. Verified on 2026-09-18:
the setting is already on for all three projects, and each served the pushed SHA within about a
minute of the push, so nothing needed changing.

This half matters more than the backend half, not less: failure 3 was a *frontend* serving April's
code, and a stale static build is exactly what a 200 check cannot see.

**What this still requires that does not exist yet:**

- Step 5 of the check above, hitting one real functional endpoint and asserting its shape, is
  deliberately not implemented. Each repo's real endpoints fan out to paid third-party APIs
  (ThreatScan to eleven threat-intel providers, PromptShield and SOCTriage to LLM providers), so
  running one on every push spends quota and imports someone else's availability into this repo's
  CI signal. It belongs in a scheduled smoke test with its own budget, not in the deploy gate.

---

## Per-repo current state

Read from the repos on 2026-09-13. Rows marked "platform-verified" were confirmed on Railway and
Vercel rather than in the repo. Anything that was neither read from the repo nor checked on the
platform is marked unverified. ThreatScan's deploy state is the one gap: it was not checked.

| | PromptShield | ThreatScan | SOCTriage |
|---|---|---|---|
| **Workflow files** | `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `.github/workflows/uptime.yml`, `.github/workflows/deploy-verify.yml` | `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `.github/workflows/deploy-verify.yml` | `.github/workflows/backend-tests.yml`, `.github/workflows/security.yml`, `.github/workflows/deploy-verify.yml` |
| **CI jobs** | 12 across two workflows. `ci.yml` has 7: test (Python 3.11/3.12/3.13 matrix), lint (ruff), typecheck (mypy strict), backend (clean prod install + pytest), frontend (eslint + vite build + vitest). `security.yml` has 5: pip-audit, npm audit, gitleaks, CodeQL (python), CodeQL (javascript-typescript) | 6 across two workflows. `ci.yml` has 2: backend (jest with coverage, `node --check server.js`), frontend (eslint + vite build + vitest). `security.yml` has 4: npm audit (backend), npm audit (frontend), gitleaks, CodeQL (javascript-typescript) | 6 across two workflows. `backend-tests.yml` has 1: pytest with coverage. `security.yml` has 5: pip-audit, npm audit, gitleaks, CodeQL (python), CodeQL (javascript-typescript) |
| **Backend tests** | 261 test functions in `tests/`, 62 in `backend/tests/` | 152 tests across 13 jest files | 62 test functions across 4 files |
| **Frontend tests** | Yes. 2 vitest files, added 2026-09-04 (`78ce0b5`) | Yes. 4 vitest files, added 2026-09-11 (`f6a5925`) | **None.** No test script in `frontend/package.json`, no frontend CI job |
| **Lint in CI** | Yes, both sides (ruff + eslint) | Frontend only. No backend linter | **No.** `eslint` is in `frontend/package.json` but never runs in CI |
| **Type checking** | Yes, mypy strict on `promptshield/` | No | No |
| **Coverage reporting** | Codecov, from the 3.13 matrix leg | Codecov, backend only | Codecov, backend only |
| **Deploy config in repo** | `railway.json` (backend), `backend/Procfile`, `backend/runtime.txt` | None in repo. README documents manual Railway and Vercel setup | `backend/Procfile`, `backend/runtime.txt`. No `railway.json` |
| **Deploy git-connected** | Yes, both. Railway and Vercel are git-connected and deploying (platform-verified) | Yes, both. Railway auto-deploys the backend on push to `main`, observed directly on 2026-09-16: two pushes each produced a restart within about two minutes, confirmed by the `uptime` field in the health response resetting. Vercel frontend is live and serving | Yes, both. Vercel is git-connected to `main` and auto-deploying, verified by a push triggering a build within 30 seconds. It was disconnected as of the 2026-09-11 audit |
| **Railway build health** | Building and deploying (platform-verified) | Building and deploying. Observed redeploying on push and serving a healthy 11-engine fan-out afterwards | Fixed. Was failing since June on a mise attestation failure for the pinned Python version, worked around with `MISE_PYTHON_GITHUB_ATTESTATIONS=false`. See the technical debt section |
| **Database** | None | None | Postgres on Railway, attached with `DATABASE_URL` set (platform-verified: `created_at` returns with a `Z` suffix). `backend/database.py` still falls back to `sqlite:///./soctriage.db` when `DATABASE_URL` is unset, which is correct for local development but was the ephemeral-storage bug in production |
| **Monitoring** | Uptime and health, every 15 minutes, from `uptime.yml` in this repo. Backend health endpoint plus frontend. Post-deploy SHA verification of backend and frontend on every push, from this repo's own `deploy-verify.yml` | Same uptime monitor, run from PromptShield's `uptime.yml`. Post-deploy SHA verification of backend and frontend from its own `deploy-verify.yml` | Same uptime monitor, run from PromptShield's `uptime.yml`. Post-deploy SHA verification of backend and frontend from its own `deploy-verify.yml` |
| **Dependency bot** | **None.** No `dependabot.yml` or `renovate.json` | **None** | **None** |
| **Secret scanning** | Yes. gitleaks over the full git history on push, pull request, and weekly. Pinned release, checksum-verified, `--redact` so findings are not republished into a public Actions log | Yes, same configuration. History scanned for the first time on 2026-09-16 and clean | Yes, same configuration. History scanned for the first time on 2026-09-16 and clean |
| **Vulnerability scanning** | Yes. pip-audit over both Python trees (root package and `backend/requirements.txt`) and `npm audit --omit=dev` over the frontend production tree, on push, pull request, and weekly | Yes. `npm audit --omit=dev` over the backend and frontend production trees as two separate jobs. Both clean as of 2026-09-16, after the backend bump described below | Yes. pip-audit over `backend/requirements.txt` and `npm audit --omit=dev` over the frontend production tree. Both clean as of 2026-09-16, after the fastapi bump described below |
| **CodeQL** | Yes. `python` and `javascript-typescript`, on push, pull request, and weekly. Alerts go to the Security tab and do not fail the workflow | Yes. `javascript-typescript`. Zero open alerts on first run | Yes. `python` and `javascript-typescript`. Zero open alerts on first run |

Notes on the table:

- Python test counts come from counting test function definitions in the source. The actual number
  of collected cases will be higher wherever parametrization is used. SOCTriage's README claims a
  "71-test pytest suite"; the repo has 62 `def test_` definitions. **Verified by running it on
  2026-09-16: pytest collects exactly 71 from those 62 definitions, so the README was right and the
  source count was the misleading one.** PromptShield's Python numbers are still source counts and
  have not been reconciled the same way.
- ThreatScan's figure is jest's own count from a real run, which is why it is the most trustworthy
  number in the row. It was previously recorded here as "229 `it()` blocks", which was wrong: that
  grep descended into `node_modules` and counted test files belonging to dependencies. The suite is
  152 tests across 13 files. A counting method that can silently include a dependency's tests is not
  a counting method worth trusting, and the same caveat applies to the Python numbers above.
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

## Resolved findings: SOCTriage backend dependencies

SOCTriage's first `pip-audit` run found 8 advisories in the backend dependency tree. **All eight
were cleared on 2026-09-16** in commit `71dfa67`, which bumped `fastapi` 0.115.0 to 0.141.1 (pulling
starlette 0.38.6 to 1.6.0) and `python-dotenv` 1.0.1 to 1.2.2.

| Package | Version | Advisory | Fixed in |
|---|---|---|---|
| `starlette` | 0.38.6 | Missing Host header validation poisons `request.url.path`, bypassing path-based security checks | 1.0.1 |
| `starlette` | 0.38.6 | Unvalidated request path concatenated into authority poisons `request.url.hostname` | 1.3.0 |
| `starlette` | 0.38.6 | Arbitrary HTTP method dispatched to `HTTPEndpoint` attributes via `getattr` | 1.1.0 |
| `starlette` | 0.38.6 | SSRF and NTLM credential theft via UNC paths in `StaticFiles` on Windows | 1.1.0 |
| `starlette` | 0.38.6 | `request.form()` limits silently ignored for urlencoded bodies, enabling denial of service | 1.3.1 |
| `starlette` | 0.38.6 | Denial of service parsing large files in multipart forms | 0.47.2 |
| `starlette` | 0.38.6 | Denial of service via `multipart/form-data` | 0.40.0 |
| `python-dotenv` | 1.0.1 | Symlink following in `set_key` allows arbitrary file overwrite via cross-device rename fallback | 1.2.2 |

**The interesting part is that starlette is not in `requirements.txt`.** It is reached transitively
through `fastapi==0.115.0`, which pins it below 0.39. Reading the file would never have surfaced
this; auditing the resolved tree did. That is the argument for auditing what gets installed rather
than what is written down.

**This was not a one-command fix, unlike ThreatScan's.** `python-dotenv` moved on its own, but every
starlette advisory needed fastapi bumped first, since the pin was what held starlette back. That is a
real upgrade of the web framework this service runs on, not a lockfile refresh, so it was verified by
diffing the old and new stacks rather than by trusting a green suite.

**Two real behaviour changes were found:**

- `include_router` no longer flattens routes into `app.routes`. There is now a single
  `_IncludedRouter` entry holding them, so `app.routes` drops from 12 entries to 6. Routing, the
  OpenAPI paths and every endpoint are unaffected, and nothing in this repo introspects `app.routes`.
- CORS simple requests under `allow_origins=["*"]` now reflect the calling origin instead of
  returning a literal `*`. Production is unaffected because it sets `FRONTEND_URL` to the Vercel
  frontend and never takes the wildcard path, which was confirmed against the deployed service
  before and after. It applies to local development, where the wildcard default is used.
- A third, smaller one is visible to clients: 422 validation bodies now carry `input` and `ctx`
  alongside `loc`, `msg` and `type`. Additive, so a client reading the existing fields is unaffected.

**What the tests could not cover.** SOCTriage has no linter and no type checker, so nothing would
catch a changed function signature, a renamed keyword argument, or a drifted type annotation that the
71 tests happen not to exercise. The tests also never touch `app.routes`, CORS headers, or the
OpenAPI schema, which is precisely where all three real changes landed. They were found by running an
identical probe against both stacks and diffing the output, not by the suite going green. Adding
ruff and mypy here is the durable fix; it is recorded as a gap rather than done.

**On how much these mattered here.** Several of the starlette advisories concern multipart form
parsing and `StaticFiles`, and SOCTriage serves neither, which was verified by searching the backend
for `StreamingResponse`, `StaticFiles`, `UploadFile`, `File(`, `Form(`, `multipart` and `WebSocket`
and finding none. Its eight endpoints take JSON and return JSON, and static files are served by
Vercel, not by this app. The two host-header advisories are the
ones worth taking seriously, since they poison `request.url` and this app is a public unauthenticated
API. None of this is a reason to leave the bump undone; it is a reason not to treat the count of 8 as
the measure of the risk.

**Verified in production, not just in CI.** Railway redeployed within about a minute of the push,
confirmed by the deployed `/openapi.json` gaining the `ctx` and `input` fields that only the new
fastapi emits, since this service's health endpoint reports a hardcoded version and cannot answer the
question directly. The live service was then exercised end to end: health, a real triage returning 11
enrichment engines and an AI report with five MITRE techniques, a `PATCH` status update, a read-back
confirming persistence, a 422 on an invalid enum, and the dashboard. CORS behaviour against the
deployed service was byte-for-byte identical before and after.

**Nothing was suppressed.** No advisory was ignored and no threshold was raised.

---

## Resolved findings: ThreatScan backend dependencies

ThreatScan's first `npm audit` run found 5 advisories in the **backend production tree**, the code
that actually serves requests on Railway. **All five were cleared on 2026-09-16** in commit
`24cb4eb`, and the job is green. Recorded here because the first thing this scanner caught was a real
exposure in a deployed service, which is the whole argument for Tier 1.

| Package | Severity | Direct | Advisory |
|---|---|---|---|
| `axios` | high | yes | Prototype pollution, `maxBodyLength` bypasses, proxy handling, formDataToJSON recursion |
| `form-data` | high | transitive | CRLF injection via unescaped multipart field names |
| `express` | moderate | yes | Depends on a vulnerable `qs` |
| `qs` | moderate | transitive | Array-limit bypass, denial of service via attacker-controlled `isBuffer` |
| `body-parser` | moderate | transitive | Denial of service when an invalid limit silently disables size enforcement |

**Every one had a semver-compatible fix.** None required a major version bump, so `npm audit fix`
resolved all 5 inside the ranges already declared in `backend/package.json`, which was left
untouched. Production dependencies moved: `axios` 1.16.1 to 1.20.0, `express` 4.22.2 to 4.22.3, `qs`
6.15.2 to 6.16.0, `body-parser` 1.20.5 to 1.20.8, `form-data` 4.0.5 to 4.0.6.

**Nothing was suppressed to make this green.** The threshold was not raised, no advisory was
ignored, and `--omit=dev` narrows scope to the deployed tree rather than hiding anything: the dev
tree here is jest, nodemon and supertest, which never run in production. The finding is real and the
red check is the correct signal.

**How it was verified.** The jest suite mocks axios in every engine test, so 152 passing tests say
nothing about whether the upgrade works. The real HTTP path was exercised separately: a JSON POST, a
urlencoded POST, and a GET through the keyless engines locally, then a live scan against the
redeployed service returning all 11 engines with real data. No engine sets `proxy`, `maxBodyLength`,
`maxContentLength`, `paramsSerializer` or `transformRequest`, and none passes a plain object as a
POST body, so the axios fixes in that range land in code paths this service does not use.

This is a reminder worth keeping: a green test suite that mocks its dependency cannot validate a
dependency upgrade. Something has to touch the real thing.

This is also the first genuine demonstration that Tier 1 works. The scanners found something that
was already true, already deployed, and invisible from outside, which is the entire premise of the
plan.

---

## Resolved findings: CodeQL on `detect_provider`

CodeQL's first run opened two high-severity alerts, both
`py/incomplete-url-substring-sanitization`, at `promptshield/engines/api_scanner.py:61` and `:63`.
**Both are fixed and CodeQL closed them automatically on 2026-09-14** (commit `72dfb57`). Recorded
here because the first thing Tier 1 caught is worth keeping a record of.

The host checks were substring tests over the whole URL:

```python
if "anthropic.com" in url_lower or "/v1/messages" in url_lower:
```

A substring test is not a host test. `anthropic.com` matched `anthropic.com.example.net`, a
lookalike domain someone else controls, and `example.net/?ref=anthropic.com`, where the name only
appears in a query string.

**The fix** parses the URL and compares the host, matching the domain itself or a subdomain on the
dot boundary. `urlsplit().hostname` also normalizes case and strips userinfo and port, and a
malformed URL now resolves to no host rather than raising.

A follow-up commit (`65c07ff`) applied the same reasoning one component over. The endpoint-shape
checks for `/v1/messages` and `/chat/completions` were still substring tests over the whole URL,
which meant `https://example.net/api?ref=/v1/messages` detected as Anthropic on the strength of a
query string, and a fragment did the same. They now match inside `urlsplit(url).path`. They remain
substring tests of the path rather than exact matches, because a compatible server is identified by
the endpoint shape it exposes wherever it is hosted and whatever prefix it is mounted under.

Twenty-two tests cover the two changes. The nine bypass cases were each run against the
implementation they replaced and confirmed to fail against it, rather than assumed to. The
host-matching tests avoid `/v1/messages` and `/chat/completions` entirely, and the path-matching
tests are all hosted on `example.net`, so neither kind of check can hide behind the other passing.

**On severity.** These were labelled high, and the rule was right about the code, but the practical
exposure was lower than the label: the URL is operator-supplied rather than attacker-controlled, and
the return value picks a request format rather than making a trust decision. They were still worth
fixing. The check is now correct as well as safe, and the function no longer carries a footgun for
whoever reuses it somewhere the URL is less trusted. The argument for fixing a finding is not only
what it costs today.

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
- `PATCH /api/cases/{case_id}/status`
- `PATCH /api/cases/{case_id}/note`
- `PATCH /api/cases/{case_id}/close`
- `GET /api/dashboard`

**Corrected 2026-09-16: there are eight endpoints, not the five recorded here previously.** The three
`PATCH` routes were missed because the grep that enumerated them listed `get`, `post`, `put` and
`delete` and omitted `patch`. That correction makes the gap worse rather than cosmetic: it is not one
unauthenticated write endpoint but four, and three of them mutate the state of an existing case.

`GET /api/cases` returns every case in the database to any caller. `POST /api/triage` writes to it,
and the three `PATCH` routes let any caller change a case's status, append an analyst note, or close
a case with an arbitrary resolution. So an anonymous caller can read the stored case data, add to it,
and rewrite the audit-relevant parts of it. Now that Postgres is attached and the data actually
survives restarts, this matters more than it did in September, not less: the ephemeral storage bug
was destroying the same data that has no access control on it. There is also no audit logging, so a
change made this way leaves no record of who made it.

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

**Step 1. External uptime and health monitoring on all six deployed surfaces. DONE 2026-09-14.**
First because it is the only item that catches a live outage today, with no code change and no CI
change. Three backends, three frontends, alerts going to the repository owner on failure. Shipped as
`uptime.yml` on a 15 minute schedule rather than the five minutes sketched here, for the reasons in
1.5. All six surfaces were confirmed healthy at the time it went in.

**Step 2. Secret scanning (gitleaks) across all three repos. DONE for PromptShield 2026-09-13.**
Second because it is the highest-severity thing that could already be wrong with nobody knowing.
Unlike the other scanners, a finding here is an emergency rather than a backlog item, and the
full-history scan either finds something or permanently retires the worry. PromptShield's history is
clean across all 108 commits, and ThreatScan's and SOCTriage's are clean too as of 2026-09-16, each
scanned for the first time. **All three repos are now covered, and none of the three has ever
committed a secret.**

**Step 3. Build identity in every health response, then post-deploy verification. DONE for all
three backends 2026-09-17.** Third because it needs a code change in all three repos (the commit SHA
plumbing) and is therefore slower than steps 1 and 2, but it is the step that specifically closes
the stale-build failure mode. Once a health response reports the SHA it is running, a five-line
check after every deploy makes a disconnected Vercel project impossible to miss.

Shipped as a `commit` field in all three health responses, a `<meta name="build-commit">` tag in all
three frontends, and a `deploy-verify.yml` in each repo that checks both of its surfaces in parallel
jobs; see the deploy verification section for what it asserts and what it deliberately does not.
**All six deployed surfaces can now be asked what they are running**, including the three where the
original failure actually happened.

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
