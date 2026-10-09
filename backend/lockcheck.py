"""Whether the running process has exactly the dependency versions in the lock.

backend/requirements.txt is a hashed lock compiled from requirements.in, and
production installs from it. This module answers one question at startup, for
/health: does every package the lock pins match the version that is actually
installed? It reports a single boolean and never the versions themselves, so
the health endpoint does not publish a list of what to look up advisories for.

How a lock line is judged:

  * ``name==version`` with no environment marker: the package must be
    installed at exactly that version.
  * ``name==version ; <marker>``: the lock is universal, so some lines apply
    only to some platforms (an emscripten-only package, say). Markers are not
    evaluated here, because that needs the ``packaging`` library, which the
    lock does not otherwise install. Such a line is checked only when the
    package is installed: installed at another version is a mismatch, absent
    is taken as the marker excluding it.

Anything that stops the check from running (no lock file, an unreadable one)
answers False, never True: a check that cannot run has not confirmed anything.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

LOCK_PATH = Path(__file__).resolve().parent / "requirements.txt"

# "name==version" at the start of a line, then an optional "; marker". Lines
# starting with whitespace (hashes, "# via" notes) or "#" never match.
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(;)?")


def locked_pins(text: str) -> list[tuple[str, str, bool]]:
    """``(name, version, has_marker)`` for every pinned line of a lock."""
    pins = []
    for line in text.splitlines():
        match = _PIN.match(line)
        if match:
            pins.append((match.group(1), match.group(2), match.group(3) is not None))
    return pins


def _installed_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def dependencies_locked(
    lock_path: Path = LOCK_PATH,
    installed_version: Callable[[str], str | None] = _installed_version,
) -> bool:
    """True when every pin in the lock matches what is installed."""
    try:
        pins = locked_pins(lock_path.read_text(encoding="utf-8"))
    except OSError:
        return False
    if not pins:
        return False
    for name, pinned, has_marker in pins:
        found = installed_version(name)
        if found is None:
            if has_marker:
                continue
            return False
        if found != pinned:
            return False
    return True
