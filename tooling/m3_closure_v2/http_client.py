from __future__ import annotations

import email.utils
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol

from .errors import HttpVerificationError


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def __call__(self, url: str, timeout_s: float) -> HttpResponse: ...


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 8
    base_delay_s: float = 0.5
    max_delay_s: float = 30.0
    minimum_interval_s: float = 0.15
    timeout_s: float = 15.0
    retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504})

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if self.base_delay_s < 0 or self.max_delay_s < 0:
            raise ValueError("retry delays must be nonnegative")
        if self.minimum_interval_s < 0:
            raise ValueError("minimum_interval_s must be nonnegative")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")


@dataclass
class RequestAttempt:
    attempt: int
    status: int
    delay_before_retry_s: float
    retry_after_header: str
    error: str = ""


@dataclass
class RequestTrace:
    url: str
    attempts: list[RequestAttempt] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "attempts": [
                {
                    "attempt": item.attempt,
                    "status": item.status,
                    "delay_before_retry_s": item.delay_before_retry_s,
                    "retry_after_header": item.retry_after_header,
                    "error": item.error,
                }
                for item in self.attempts
            ],
        }


def urllib_transport(url: str, timeout_s: float) -> HttpResponse:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            return HttpResponse(
                status=int(response.status),
                headers={str(k): str(v) for k, v in response.headers.items()},
                body=response.read(4 * 1024 * 1024),
            )
    except urllib.error.HTTPError as exc:
        return HttpResponse(
            status=int(exc.code),
            headers={str(k): str(v) for k, v in exc.headers.items()},
            body=exc.read(4 * 1024 * 1024),
        )


def _retry_after_seconds(
    raw: str,
    *,
    wall_clock: Callable[[], float],
) -> float | None:
    value = str(raw or "").strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        now = datetime.fromtimestamp(wall_clock(), timezone.utc)
        return max(0.0, (parsed - now).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


class RateLimitedJsonClient:
    """Sequential JSON client with deterministic pacing and bounded retries.

    Concurrency is intentionally one for evidence replay.  This is a valid
    bounded-concurrency policy and avoids turning a verification pass into a
    rate-limit load test.
    """

    def __init__(
        self,
        base_url: str,
        *,
        policy: RetryPolicy | None = None,
        transport: Transport = urllib_transport,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.base_url = str(base_url).rstrip("/")
        if not self.base_url:
            raise ValueError("base_url is required")
        self.policy = policy or RetryPolicy()
        self.transport = transport
        self.sleeper = sleeper
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self._last_request_started: float | None = None
        self.traces: list[RequestTrace] = []

    def _paced_start(self) -> None:
        if self._last_request_started is not None:
            elapsed = self.monotonic() - self._last_request_started
            remaining = self.policy.minimum_interval_s - elapsed
            if remaining > 0:
                self.sleeper(remaining)
        self._last_request_started = self.monotonic()

    def _url(self, path: str) -> str:
        suffix = str(path)
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return self.base_url + suffix

    def get_json(self, path: str) -> dict[str, Any]:
        url = self._url(path)
        trace = RequestTrace(url=url)

        for attempt in range(1, self.policy.max_attempts + 1):
            self._paced_start()
            response = self.transport(url, self.policy.timeout_s)
            retry_after_header = str(
                response.headers.get("Retry-After")
                or response.headers.get("retry-after")
                or ""
            )

            if 200 <= response.status < 300:
                try:
                    parsed = json.loads(response.body.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise HttpVerificationError(
                        f"json_response_invalid:{url}"
                    ) from exc
                if not isinstance(parsed, dict):
                    raise HttpVerificationError(
                        f"json_response_not_object:{url}"
                    )
                trace.attempts.append(
                    RequestAttempt(
                        attempt=attempt,
                        status=response.status,
                        delay_before_retry_s=0.0,
                        retry_after_header=retry_after_header,
                    )
                )
                self.traces.append(trace)
                return parsed

            retriable = response.status in self.policy.retry_statuses
            if not retriable or attempt >= self.policy.max_attempts:
                trace.attempts.append(
                    RequestAttempt(
                        attempt=attempt,
                        status=response.status,
                        delay_before_retry_s=0.0,
                        retry_after_header=retry_after_header,
                        error="retry_exhausted" if retriable else "non_retriable",
                    )
                )
                self.traces.append(trace)
                raise HttpVerificationError(
                    f"http_request_failed:"
                    f"status={response.status}:attempt={attempt}:url={url}"
                )

            retry_after = _retry_after_seconds(
                retry_after_header,
                wall_clock=self.wall_clock,
            )
            exponential = min(
                self.policy.max_delay_s,
                self.policy.base_delay_s * (2 ** (attempt - 1)),
            )
            delay = min(
                self.policy.max_delay_s,
                retry_after if retry_after is not None else exponential,
            )
            trace.attempts.append(
                RequestAttempt(
                    attempt=attempt,
                    status=response.status,
                    delay_before_retry_s=delay,
                    retry_after_header=retry_after_header,
                )
            )
            self.sleeper(delay)

        raise AssertionError("bounded retry loop exited unexpectedly")
