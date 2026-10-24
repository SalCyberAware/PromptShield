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

CI in ThreatScan and SOCTriage pulls without logging in, so each mirror package must be public.

Two GitHub rules decide the order of the first runs:

- GHCR creates a package as **private** the first time something is pushed to it, and a package can only be made public once it exists.
- A GitHub Free personal account has **500 MB** of private package storage. Pushes to private packages are blocked once it is used up. Public packages are free, with no size limit.

The base images are about 5 to 6 GB, so a first real run straight into new private packages fails on the first big image. Do not start with a real run. Instead:

1. **Seed run.** Actions, **Mirror base images**, **Run workflow**, tick **Seed** and untick **Dry run**. This pushes one placeholder image per package, tagged `seed`: a single empty layer built by crane, under 1 KB, with nothing pulled from upstream. A package that already has its `seed` tag is skipped. The job summary lists each package with its size. With **Dry run** still ticked, the seed run only lists the packages it would create and pushes nothing.
2. **Sal makes each package public.** For each of `mirror/python`, `mirror/node`, `mirror/postgres` and `mirror/adobe/s3mock`:
   1. github.com, your profile, **Packages**.
   2. Open the package.
   3. **Package settings**, **Danger Zone**, **Change visibility**, **Public**, then type the package name to confirm.
3. **Real run.** **Run workflow** with **Seed** and **Dry run** both unticked (or wait for the Thursday run). The copies now go into public packages.

The `seed` tag can stay. The normal run never reads, moves or deletes it, and refuses an upstream image whose tag is `seed`.

A new image (a new package name) needs the same three steps: a seed run, make the new package public, then the real run.

## How a new pin reaches the mirror

- **Weekly:** the workflow runs on Thursdays at 06:30 UTC, an hour before the base image watch. It reads `main` of all three repos.
- **Now:** Actions, **Mirror base images**, **Run workflow**. Untick **Dry run** to copy. With the box ticked it only lists what it would copy. Leave **Seed** unticked.

So after merging a pin change, run the workflow by hand (or wait for Thursday) before pointing CI at the new digest in the mirror.

A failed copy (for example a 429 that outlasts the retries) fails the run after all other images were tried. The next run tries again.

## Railway is not affected

Railway builds the Dockerfiles, and those keep pulling from public.ecr.aws. Nothing in this mirror changes a deployed image.

## Running it locally

```bash
.github/scripts/mirror-base-images.sh --self-test     # no network
DRY_RUN=true .github/scripts/mirror-base-images.sh \
  PromptShield=. ThreatScan=../ThreatScan SOCTriage=../SOCTriage
DRY_RUN=true .github/scripts/mirror-base-images.sh --seed \
  PromptShield=. ThreatScan=../ThreatScan SOCTriage=../SOCTriage
```

Needs bash 4, git, sha256sum and crane. The dry run reads anonymously and copies nothing.
