"""Where provider keys come from when running from a checkout.

Provider keys live in ``backend/.env`` -- the file the local backend runs on --
with the repo-root ``.env`` kept for CLI-only settings. The CLI used to call a
bare ``load_dotenv()``, which finds the root file only, so a key that exists
only in ``backend/.env`` was invisible to ``promptshield eval``: a live scoring
run reported no Gemini fallback while the backend, and the seed script, could
see one. This loads both, in the seed script's order.
"""
from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

#: The checkout this package was installed from, when it is an editable install.
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def env_files(cwd: Path | None = None) -> list[Path]:
    """The ``.env`` files to load, in precedence order, that exist.

    ``backend/.env`` before the root one, from the working directory and then
    from the checkout the package lives in, without repeats.
    """
    roots: list[Path] = []
    for root in ((cwd or Path.cwd()).resolve(), _PACKAGE_ROOT):
        if root not in roots:
            roots.append(root)
    files: list[Path] = []
    for root in roots:
        for candidate in (root / "backend" / ".env", root / ".env"):
            if candidate.is_file() and candidate not in files:
                files.append(candidate)
    return files


def load_env_files(cwd: Path | None = None) -> list[Path]:
    """Load every file from :func:`env_files`; return the ones loaded.

    ``override=False`` throughout: a variable already set in the environment
    wins, and an earlier file wins over a later one.
    """
    loaded = env_files(cwd)
    for path in loaded:
        load_dotenv(path, override=False)
    return loaded
