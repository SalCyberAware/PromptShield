# PromptShield API image (the deployed web backend). Railway builds this file
# from the repo root (railway.json selects it), and anyone can build and run it:
#
#   docker build -t promptshield-api .
#   docker run -p 8080:8080 --env-file backend/.env promptshield-api
#
# Base: the official Python 3.12 slim image, pinned by digest so a rebuild
# cannot pick up a different image. 3.12 matches the lock's --python-version
# (backend/requirements.txt header). Dependabot's docker entry proposes digest
# updates and holds the minor. Both stages name the same image.
#
# Pulled from Amazon's public mirror of Docker Hub's official images
# (public.ecr.aws/docker/library) rather than Docker Hub itself: Docker Hub
# refuses anonymous pulls from shared builders, which failed both CI and
# Railway's build. The digest is the same image index Docker Hub serves, so
# the mirror can only supply that exact image or the build fails.

# ── Build stage ─────────────────────────────────────────────────────────────
FROM public.ecr.aws/docker/library/python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

# The runtime virtualenv gets the hashed lock and nothing else. It goes first,
# on its own layer, so a code change does not reinstall dependencies.
# --require-hashes refuses any file whose hash is not in the lock.
COPY backend/requirements.txt backend/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r backend/requirements.txt

# The engine is built into a wheel in a separate, throwaway virtualenv whose
# build backend (setuptools, wheel) comes from its own hashed lock. With
# --no-build-isolation pip uses that pinned backend instead of downloading the
# newest match, and the build tools never reach the runtime virtualenv.
COPY backend/build-requirements.txt backend/build-requirements.txt
RUN python -m venv /opt/buildenv \
 && /opt/buildenv/bin/pip install --require-hashes --no-deps -r backend/build-requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY promptshield/ promptshield/
RUN /opt/buildenv/bin/pip wheel --no-deps --no-build-isolation --wheel-dir /wheels . \
 && /opt/venv/bin/pip install --no-deps /wheels/promptshield-*.whl \
 && /opt/venv/bin/pip check

# ── Runtime stage ───────────────────────────────────────────────────────────
FROM public.ecr.aws/docker/library/python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=build /opt/venv /opt/venv

# The API imports its siblings (scan.py, limits.py, lockcheck.py) from the
# working directory, as `cd backend && uvicorn main:app` did. lockcheck.py
# reads requirements.txt at startup for /api/health. Files stay owned by root,
# so the process cannot rewrite its own code.
WORKDIR /app/backend
COPY backend/*.py backend/requirements.txt ./

USER 10001

# The same uvicorn flags as before. A shell so ${PORT} expands (Railway sets
# it; 8080 matches the public domain's target port), and exec so uvicorn
# replaces the shell as PID 1 and receives SIGTERM, which it handles with a
# graceful shutdown.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '8080'), timeout=4)"]
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port \"${PORT:-8080}\""]
