from __future__ import annotations

import json

import pytest

from m3_closure_v2.errors import HttpVerificationError
from m3_closure_v2.http_client import (
    HttpResponse,
    RateLimitedJsonClient,
    RetryPolicy,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def wall_clock(self) -> float:
        return 0.0

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


def test_retries_429_using_retry_after_then_succeeds() -> None:
    responses = iter(
        [
            HttpResponse(429, {"Retry-After": "2"}, b'{"error":"rate"}'),
            HttpResponse(200, {}, json.dumps({"ok": True}).encode()),
        ]
    )
    clock = FakeClock()
    client = RateLimitedJsonClient(
        "http://example.test",
        policy=RetryPolicy(
            max_attempts=3,
            minimum_interval_s=0.0,
            base_delay_s=0.1,
            max_delay_s=10.0,
        ),
        transport=lambda _url, _timeout: next(responses),
        sleeper=clock.sleep,
        monotonic=clock.monotonic,
        wall_clock=clock.wall_clock,
    )

    assert client.get_json("/status") == {"ok": True}
    assert clock.sleeps == [2.0]
    assert [item.status for item in client.traces[0].attempts] == [429, 200]


def test_retry_budget_is_bounded() -> None:
    clock = FakeClock()
    client = RateLimitedJsonClient(
        "http://example.test",
        policy=RetryPolicy(
            max_attempts=3,
            minimum_interval_s=0.0,
            base_delay_s=0.25,
            max_delay_s=1.0,
        ),
        transport=lambda _url, _timeout: HttpResponse(429, {}, b"{}"),
        sleeper=clock.sleep,
        monotonic=clock.monotonic,
        wall_clock=clock.wall_clock,
    )

    with pytest.raises(HttpVerificationError, match="status=429:attempt=3"):
        client.get_json("/status")

    assert clock.sleeps == [0.25, 0.5]
