# Base image mirror

## What it is

`ghcr.io/salcyberaware/mirror` holds copies of the base images that PromptShield, ThreatScan and SOCTriage pin by digest. CI jobs failed with public.ecr.aws `429 Data limit exceeded`, most often on service containers such as the test Postgres. GitHub pulls those before any step runs, so a retrying pull step cannot help. GitHub runners pull from GHCR without that limit.

The workflow `.github/workflows/mirror-base-images.yml` in this repo keeps the mirror up to date. The logic is in `.github/scripts/mirror-base-images.sh`.

## Same digests

Every `image:tag@sha256:...` pin in the three repos' Dockerfiles and workflow `image:` lines is copied with `crane copy`. crane copies the manifest bytes unchanged, including every platform of a multi-platform image, so the copy has the same digest as the original. After each copy the script reads the manifest back from the mirror and checks that it hashes to the pinned digest.

| Upstream | Mirror |
|---|---|
| `public.ecr.aws/docker/library/python:3.12-slim-trixie@sha256:X` | `ghcr.io/salcyberaware/mirror/python:3.12-slim-trixie@sha256:X` |
| `public.ecr.aws/docker/library/node:24-trixie-slim@sha256:X` | `ghcr.io/salcyberaware/mirror/node:24-trixie-slim@sha256:X` |
| `public.ecr.aws/docker/library/postgres:18@sha256:X` | `ghcr.io/salcyberaware/mirror/postgres:18@sha256:X` |
| `adobe/s3mock:5.2.3@sha256:X` | `ghcr.io/salcyberaware/mirror/adobe/s3mock:5.2.3@sha256:X` |

The mirror name is the path after the registry, without `docker/library/` (or `library/` on Docker Hub).

- Every pinned digest stays pullable by digest, also after its tag moves on.
- The mirror tag points at the digest the upstream tag points at now, so it can run ahead of the pins. Pull by digest, never by tag alone.
- A digest that is already in the mirror is not copied again.

## Packages must be public

GHCR creates each package as private the first time something is pushed to it. CI in ThreatScan and SOCTriage pulls without logging in, so each package must be public. Sal sets this once per package after the first real run:

1. GitHub, your profile, **Packages**.
2. Open each `mirror/...` package.
3. **Package settings**, **Danger Zone**, **Change visibility**, **Public**, then type the package name to confirm.

A new image (a new package name) needs the same step once, after the run that first copies it.

## How a new pin reaches the mirror

- **Weekly:** the workflow runs on Thursdays at 06:30 UTC, an hour before the base image watch. It reads `main` of all three repos.
- **Now:** Actions, **Mirror base images**, **Run workflow**. Untick **Dry run** to copy. With the box ticked it only lists what it would copy.

So after merging a pin change, run the workflow by hand (or wait for Thursday) before pointing CI at the new digest in the mirror.

A failed copy (for example a 429 that outlasts the retries) fails the run after all other images were tried. The next run tries again.

## How CI uses it

PromptShield's container job (**Backend container (build + smoke test)**) builds from the mirror. The Dockerfile's FROM lines stay on public.ecr.aws. For each digest-pinned FROM ref the job pulls `ghcr.io/salcyberaware/mirror/<name>:<tag>@<same digest>`, fails unless the pulled image has exactly the pinned digest, and passes `--build-context <FROM ref>=docker-image://<mirror ref>` to `docker build`, so BuildKit uses the mirror copy in place of the FROM ref. The job points public.ecr.aws at 0.0.0.0 first, so a build that tried to reach it would fail.

The FROM lines stay literal on purpose: Dependabot's docker updater and both scripts in `.github/scripts` only read a literal image on a FROM line. An `ARG BASE_IMAGE` default would hide the pin from them.

A Dependabot digest bump can only pass this job once the new digest is in the mirror. The weekly run copies the digest each upstream tag points at, so this is usually already true. If not, run the workflow by hand.

## Railway is not affected

Railway builds the Dockerfiles, and those keep pulling from public.ecr.aws. Nothing in this mirror changes a deployed image.

## Running it locally

```bash
.github/scripts/mirror-base-images.sh --self-test     # no network
DRY_RUN=true .github/scripts/mirror-base-images.sh \
  PromptShield=. ThreatScan=../ThreatScan SOCTriage=../SOCTriage
```

Needs bash 4, git, sha256sum and crane. The dry run reads anonymously and copies nothing.
