"""Unit tests for the abuse-control Limiter. Time is injected, so no real waiting."""
from __future__ import annotations

import pytest
from limits import (
    DEFAULT_DAILY_CAP,
    DEFAULT_IP_RATE,
    DEFAULT_MAX_PROMPT_CHARS,
    Limiter,
    LimitRejectedError,
    build_limiter,
)


class _Clock:
    """A controllable clock for the Limiter's time_fn."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class TestLengthCap:
    def test_oversized_prompt_rejected_400(self) -> None:
        limiter = Limiter(max_prompt_chars=10)
        with pytest.raises(LimitRejectedError) as info:
            limiter.check_and_consume("x" * 11, "1.1.1.1")
        assert info.value.status_code == 400
        assert "too long" in info.value.message

    def test_at_limit_is_allowed(self) -> None:
        limiter = Limiter(max_prompt_chars=10)
        limiter.check_and_consume("x" * 10, "1.1.1.1")  # exactly at limit, no raise

    def test_rejected_oversized_consumes_nothing(self) -> None:
        limiter = Limiter(max_prompt_chars=5, daily_cap=1)
        with pytest.raises(LimitRejectedError):
            limiter.check_and_consume("toolong", "1.1.1.1")
        # The daily slot was not taken, so a valid request still goes through.
        limiter.check_and_consume("ok", "1.1.1.1")


class TestIpRateLimit:
    def test_rejects_n_plus_1_in_window(self) -> None:
        clock = _Clock()
        limiter = Limiter(ip_rate=3, ip_window_seconds=300, time_fn=clock)
        for _ in range(3):
            limiter.check_and_consume("p", "1.1.1.1")
        with pytest.raises(LimitRejectedError) as info:
            limiter.check_and_consume("p", "1.1.1.1")
        assert info.value.status_code == 429
        assert "Retry-After" in info.value.headers
        assert int(info.value.headers["Retry-After"]) >= 1

    def test_other_ip_unaffected(self) -> None:
        limiter = Limiter(ip_rate=1)
        limiter.check_and_consume("p", "1.1.1.1")
        with pytest.raises(LimitRejectedError):
            limiter.check_and_consume("p", "1.1.1.1")
        limiter.check_and_consume("p", "2.2.2.2")  # different IP, allowed

    def test_recovers_after_window(self) -> None:
        clock = _Clock()
        limiter = Limiter(ip_rate=1, ip_window_seconds=300, time_fn=clock)
        limiter.check_and_consume("p", "1.1.1.1")
        with pytest.raises(LimitRejectedError):
            limiter.check_and_consume("p", "1.1.1.1")
        clock.advance(301)
        limiter.check_and_consume("p", "1.1.1.1")  # window passed, allowed again

    def test_rejected_rate_consumes_no_daily_slot(self) -> None:
        limiter = Limiter(ip_rate=1, daily_cap=5)
        limiter.check_and_consume("p", "1.1.1.1")  # daily = 1
        with pytest.raises(LimitRejectedError) as info:
            limiter.check_and_consume("p", "1.1.1.1")  # 429, must not bump daily
        assert info.value.status_code == 429
        # A different IP can still run: daily count is at 1, not 2.
        for i in range(4):
            limiter.check_and_consume("p", f"9.9.9.{i}")
        with pytest.raises(LimitRejectedError) as info2:
            limiter.check_and_consume("p", "8.8.8.8")
        assert info2.value.status_code == 503  # the 6th overall hits the daily cap of 5


class TestDailyCap:
    def test_rejects_past_global_ceiling(self) -> None:
        limiter = Limiter(daily_cap=2, ip_rate=100)
        limiter.check_and_consume("p", "1.1.1.1")
        limiter.check_and_consume("p", "1.1.1.1")
        with pytest.raises(LimitRejectedError) as info:
            limiter.check_and_consume("p", "1.1.1.1")
        assert info.value.status_code == 503
        assert "capacity" in info.value.message

    def test_resets_next_utc_day(self) -> None:
        clock = _Clock()
        limiter = Limiter(daily_cap=1, ip_rate=100, time_fn=clock)
        limiter.check_and_consume("p", "1.1.1.1")
        with pytest.raises(LimitRejectedError):
            limiter.check_and_consume("p", "1.1.1.1")
        clock.advance(86_400)  # next UTC day
        limiter.check_and_consume("p", "1.1.1.1")  # counter reset, allowed


class TestCheckOrder:
    def test_length_checked_before_daily_cap(self) -> None:
        # Daily cap already exhausted, but an oversized prompt still gets the 400.
        limiter = Limiter(max_prompt_chars=3, daily_cap=1, ip_rate=100)
        limiter.check_and_consume("ok", "1.1.1.1")  # fills the daily cap
        with pytest.raises(LimitRejectedError) as info:
            limiter.check_and_consume("toolong", "1.1.1.1")
        assert info.value.status_code == 400  # length wins, cheapest first


class TestBuildLimiter:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "PROMPTSHIELD_WEB_MAX_PROMPT_CHARS",
            "PROMPTSHIELD_WEB_IP_RATE",
            "PROMPTSHIELD_WEB_IP_WINDOW_SECONDS",
            "PROMPTSHIELD_WEB_DAILY_CAP",
        ):
            monkeypatch.delenv(var, raising=False)
        limiter = build_limiter()
        assert limiter.max_prompt_chars == DEFAULT_MAX_PROMPT_CHARS
        assert limiter.ip_rate == DEFAULT_IP_RATE
        assert limiter.daily_cap == DEFAULT_DAILY_CAP

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PROMPTSHIELD_WEB_MAX_PROMPT_CHARS", "1234")
        monkeypatch.setenv("PROMPTSHIELD_WEB_IP_RATE", "9")
        monkeypatch.setenv("PROMPTSHIELD_WEB_IP_WINDOW_SECONDS", "60")
        monkeypatch.setenv("PROMPTSHIELD_WEB_DAILY_CAP", "42")
        limiter = build_limiter()
        assert limiter.max_prompt_chars == 1234
        assert limiter.ip_rate == 9
        assert limiter.ip_window_seconds == 60
        assert limiter.daily_cap == 42

    def test_invalid_env_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PROMPTSHIELD_WEB_DAILY_CAP", "not-a-number")
        monkeypatch.setenv("PROMPTSHIELD_WEB_IP_RATE", "-3")
        limiter = build_limiter()
        assert limiter.daily_cap == DEFAULT_DAILY_CAP
        assert limiter.ip_rate == DEFAULT_IP_RATE
