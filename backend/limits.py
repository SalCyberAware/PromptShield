"""Abuse controls for the public web demo (slice 4).

Three protections, all applied before any target or judge call so a rejected
request spends nothing:
  1. system-prompt length cap (bounds per-scan cost),
  2. per-IP rate limit (bounds a single client),
  3. daily global budget cap (the backstop against total cost blow-up).

State is in-memory. This assumes a SINGLE instance and resets on restart. The
daily cap in particular resets if the process restarts mid-day, so it is a soft
backstop, not an accountant. A shared store like Redis would be the multi-instance
upgrade. All limits are env-configurable with conservative defaults.
"""
from __future__ import annotations

import math
import os
import time
from collections.abc import Callable

# Conservative defaults. Tune for deploy.
DEFAULT_MAX_PROMPT_CHARS = 8000
DEFAULT_IP_RATE = 5  # scans per IP ...
DEFAULT_IP_WINDOW_SECONDS = 300  # ... per 5 minutes
DEFAULT_DAILY_CAP = 100  # scans per UTC day across all users

_SECONDS_PER_DAY = 86400


class LimitRejectedError(Exception):
    """A request was rejected by an abuse control.

    Carries the HTTP status, a plain client-facing message, and any extra response
    headers (e.g. ``Retry-After``). The web layer maps this to an HTTP error.
    """

    def __init__(
        self, status_code: int, message: str, headers: dict[str, str] | None = None
    ) -> None:
        self.status_code = status_code
        self.message = message
        self.headers = headers or {}
        super().__init__(message)


def _env_int(name: str, default: int) -> int:
    """Read a positive int from the environment, falling back to ``default``."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


class Limiter:
    """In-memory abuse controls. Single-instance only (see module docstring).

    ``time_fn`` is injectable so tests can drive the clock with no real waiting.
    """

    def __init__(
        self,
        *,
        max_prompt_chars: int = DEFAULT_MAX_PROMPT_CHARS,
        ip_rate: int = DEFAULT_IP_RATE,
        ip_window_seconds: int = DEFAULT_IP_WINDOW_SECONDS,
        daily_cap: int = DEFAULT_DAILY_CAP,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        self.max_prompt_chars = max_prompt_chars
        self.ip_rate = ip_rate
        self.ip_window_seconds = ip_window_seconds
        self.daily_cap = daily_cap
        self._time_fn = time_fn
        self._ip_hits: dict[str, list[float]] = {}
        self._day_index: int | None = None
        self._day_count = 0

    def _roll_day(self, now: float) -> None:
        """Reset the daily counter when the UTC day changes."""
        index = int(now // _SECONDS_PER_DAY)  # UTC day index
        if index != self._day_index:
            self._day_index = index
            self._day_count = 0

    def check_and_consume(self, prompt: str, ip: str) -> None:
        """Run the checks cheapest-first and consume one slot only if all pass.

        Raises :class:`LimitRejectedError` on the first failed check, before any slot is
        taken, so a rejected request costs nothing. On success, records one usage
        against both the per-IP window and the daily counter.
        """
        # 1. Length: cheapest, no state needed.
        if len(prompt) > self.max_prompt_chars:
            raise LimitRejectedError(
                400,
                "Your system prompt is too long. The limit is "
                f"{self.max_prompt_chars} characters.",
            )

        now = self._time_fn()
        self._roll_day(now)

        # 2. Daily global cap: the hard backstop.
        if self._day_count >= self.daily_cap:
            raise LimitRejectedError(
                503,
                "The public demo is at capacity for today. Please try again "
                "tomorrow or run the CLI.",
            )

        # 3. Per-IP rate limit within the rolling window.
        recent = [
            t for t in self._ip_hits.get(ip, []) if now - t < self.ip_window_seconds
        ]
        if len(recent) >= self.ip_rate:
            retry_after = max(1, math.ceil(self.ip_window_seconds - (now - recent[0])))
            raise LimitRejectedError(
                429,
                "You are scanning too fast. Try again shortly.",
                {"Retry-After": str(retry_after)},
            )

        # All clear: consume one slot.
        recent.append(now)
        self._ip_hits[ip] = recent
        self._day_count += 1


def build_limiter() -> Limiter:
    """Build a :class:`Limiter` from environment variables with safe defaults."""
    return Limiter(
        max_prompt_chars=_env_int(
            "PROMPTSHIELD_WEB_MAX_PROMPT_CHARS", DEFAULT_MAX_PROMPT_CHARS
        ),
        ip_rate=_env_int("PROMPTSHIELD_WEB_IP_RATE", DEFAULT_IP_RATE),
        ip_window_seconds=_env_int(
            "PROMPTSHIELD_WEB_IP_WINDOW_SECONDS", DEFAULT_IP_WINDOW_SECONDS
        ),
        daily_cap=_env_int("PROMPTSHIELD_WEB_DAILY_CAP", DEFAULT_DAILY_CAP),
    )
