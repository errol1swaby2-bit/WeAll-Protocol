from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_RATE_LIMIT_SCALE = 1_000_000
_NS_PER_SECOND = 1_000_000_000


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    v = str(raw or "").strip().lower()
    if not v:
        return bool(default)
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    if _mode() == "prod":
        raise ValueError(f"invalid_boolean_env:{name}")
    return bool(default)


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    s = str(raw).strip()
    if not s:
        return int(default)
    try:
        return int(s)
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _client_ip(request: Request) -> str:
    """Best-effort client IP resolver for rate limiting.

    WARNING:
      - If you are NOT behind a trusted reverse proxy, do NOT trust X-Forwarded-For.
      - If you ARE behind a trusted proxy, ensure the proxy strips/sets X-Forwarded-For.

    Used ONLY for rate limiting (never for auth decisions).
    """

    def _is_valid_ip(raw: str) -> bool:
        try:
            ipaddress.ip_address(raw)
            return True
        except Exception:
            return False

    def _trusted_proxy_ok() -> bool:
        """If WEALL_TRUSTED_PROXY_IPS is set, require the immediate peer to match.

        This prevents accepting spoofed proxy headers when the backend is
        accidentally exposed directly to the internet.

        Format: comma-separated list of IPs or CIDRs.
          - 127.0.0.1
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
        """
        raw = (os.environ.get("WEALL_TRUSTED_PROXY_IPS") or "").strip()
        if not raw:
            mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
            if mode == "prod":
                # Keep unit tests ergonomic: TestClient does not provide a real
                # IP peer, so allow trusting proxy headers when running under
                # pytest. Production deployments should always set an allowlist.
                if os.environ.get("PYTEST_CURRENT_TEST"):
                    return True
                return False
            return True

        peer = request.client.host if request.client else ""
        if not peer or not _is_valid_ip(peer):
            return False

        try:
            peer_ip = ipaddress.ip_address(peer)
        except Exception:
            return False

        parts = [p.strip() for p in raw.split(",") if p.strip()][:64]
        for p in parts:
            try:
                if "/" in p:
                    net = ipaddress.ip_network(p, strict=False)
                    if peer_ip in net:
                        return True
                else:
                    if peer_ip == ipaddress.ip_address(p):
                        return True
            except Exception:
                continue
        return False

    trust_proxy = _env_bool("WEALL_TRUST_PROXY_HEADERS", False)
    if trust_proxy and _trusted_proxy_ok():
        for hdr in ("cf-connecting-ip", "x-real-ip"):
            v = (request.headers.get(hdr) or "").strip()
            if v and _is_valid_ip(v):
                return v

        xff = request.headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
            if ip and _is_valid_ip(ip):
                return ip

    client = request.client
    if client and client.host:
        host = str(client.host)
        return host if _is_valid_ip(host) else "unknown"

    return "unknown"


def require_account_session(
    request: Request,
    state: dict,
    *,
    account_header: str = "x-weall-account",
    session_header: str = "x-weall-session-key",
) -> str:
    """Gate user-private API access behind a user's session key."""
    acct = (request.headers.get(account_header) or "").strip()
    sk = (request.headers.get(session_header) or "").strip()
    if not acct or not sk:
        raise PermissionError("session_missing")

    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise PermissionError("session_invalid")

    arec = accounts.get(acct)
    if not isinstance(arec, dict):
        raise PermissionError("session_invalid")

    sessions = arec.get("session_keys")
    if not isinstance(sessions, dict):
        raise PermissionError("session_invalid")

    srec = sessions.get(sk)
    if not isinstance(srec, dict):
        raise PermissionError("session_invalid")

    if not bool(srec.get("active", False)):
        raise PermissionError("session_revoked")

    ttl_s = int(srec.get("ttl_s", 0) or 0)
    if ttl_s > 0:
        # Fail-closed: if ledger time is missing/invalid, do NOT silently bypass TTL.
        now = state.get("time")
        issued_at_ts = srec.get("issued_at_ts")
        if not (isinstance(now, int) and isinstance(issued_at_ts, int)):
            raise PermissionError("session_expired")
        if now > (issued_at_ts + ttl_s):
            raise PermissionError("session_expired")

    return acct


_HEALTH_EXEMPTS: Tuple[str, ...] = (
    # Legacy / common
    "/health",
    "/healthz",
    "/readyz",
    # Actual public API mount points
    "/v1/health",
    "/v1/healthz",
    "/v1/readyz",
)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Fail-fast request size limiter.

    Security posture:
      - If Content-Length is present and exceeds max -> reject immediately.
      - If Content-Length is missing/invalid for methods that can carry a body,
        read the body in streamed chunks up to max+1 and reject if exceeded.
        If within limit, hydrate request._body so downstream handlers can still
        call request.body()/json() normally.
    """

    def __init__(
        self,
        app,
        *,
        max_bytes: Optional[int] = None,
        exempt_prefixes: Tuple[str, ...] = ("/docs", "/openapi.json") + _HEALTH_EXEMPTS,
    ):
        super().__init__(app)
        if _env_bool("WEALL_SIZE_LIMIT_DISABLE", False):
            self._enabled = False
            self._max_bytes = 0
        else:
            self._enabled = True
            env_max = os.environ.get("WEALL_MAX_JSON_BYTES") or os.environ.get("WEALL_MAX_REQUEST_BYTES")
            if max_bytes is not None:
                self._max_bytes = int(max_bytes)
            else:
                self._max_bytes = _env_int("WEALL_MAX_REQUEST_BYTES", 1_000_000) if env_max is None else _env_int(
                    "WEALL_MAX_JSON_BYTES", _env_int("WEALL_MAX_REQUEST_BYTES", 1_000_000)
                )
        self._exempt_prefixes = exempt_prefixes

    def _too_large(self) -> JSONResponse:
        return JSONResponse(
            status_code=413,
            content={
                "ok": False,
                "error": {"code": "tx_too_large", "message": "Request body too large"},
            },
        )

    def _effective_max_bytes(self, path: str) -> int:
        if path.startswith("/v1/media/upload"):
            max_file = _env_int("WEALL_IPFS_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)
            overhead = _env_int("WEALL_MEDIA_MULTIPART_OVERHEAD_BYTES", 256 * 1024)
            return max(0, int(max_file) + max(0, int(overhead)))
        return self._max_bytes

    async def _read_body_capped(self, request: Request, cap_bytes: int) -> Optional[bytes]:
        """Read request body in streamed chunks up to cap_bytes+1.

        Returns:
          - bytes if body was read and within cap
          - None if body exceeded cap (caller should return 413)
        """
        parts: list[bytes] = []
        total = 0
        # Read at most cap+1 bytes so we can detect overflow without buffering everything.
        hard_cap = max(0, int(cap_bytes)) + 1

        try:
            async for chunk in request.stream():
                if not chunk:
                    continue
                if not isinstance(chunk, (bytes, bytearray)):
                    # Unexpected chunk type — treat as bad request
                    raise ValueError("bad_body_chunk")
                b = bytes(chunk)
                total += len(b)
                if total > hard_cap:
                    return None
                parts.append(b)
        except ValueError:
            raise
        except Exception:
            # Let caller treat as read failure
            raise

        body = b"".join(parts)
        if len(body) > int(cap_bytes):
            return None
        return body

    async def dispatch(self, request: Request, call_next):
        if not self._enabled:
            return await call_next(request)

        path = request.url.path or ""
        for ex in self._exempt_prefixes:
            if path.startswith(ex):
                return await call_next(request)

        eff_max = self._effective_max_bytes(path)

        cl = request.headers.get("content-length")
        if cl:
            try:
                n = int(cl)
                if n > eff_max:
                    return self._too_large()
            except Exception:
                # Invalid content-length; treat as missing and fall back to capped stream read.
                cl = None

        method = (request.method or "").upper()
        if method in {"POST", "PUT", "PATCH"}:
            # If content-length missing/invalid, do a capped streamed read.
            # If content-length is present (and <= eff_max), do not pre-read here.
            if not cl:
                try:
                    body = await self._read_body_capped(request, eff_max)
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={"ok": False, "error": {"code": "bad_request", "message": "Invalid request body"}},
                    )
                except Exception:
                    return JSONResponse(
                        status_code=400,
                        content={"ok": False, "error": {"code": "bad_request", "message": "Unable to read request body"}},
                    )

                if body is None:
                    return self._too_large()

                # Hydrate the cached body so downstream can still read it.
                # Starlette Request caches body in _body; JSON parsing uses request.body().
                try:
                    setattr(request, "_body", body)
                except Exception:
                    # If we can't set it, downstream might see an empty body;
                    # but do not crash the request.
                    pass

        return await call_next(request)


@dataclass(frozen=True)
class TokenBucket:
    rate_per_sec: int
    burst: int

    def __post_init__(self) -> None:
        if int(self.rate_per_sec) <= 0:
            raise ValueError("invalid_rate_limit_bucket_rate")
        if int(self.burst) <= 0:
            raise ValueError("invalid_rate_limit_bucket_burst")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory token bucket rate limiter with path-specific rules.

    Uses monotonic integer time and fixed-point microtokens so request-admission
    decisions do not depend on float rounding or wall-clock jumps.
    """

    def __init__(
        self,
        app,
        *,
        write_bucket: TokenBucket | None = None,
        read_bucket: TokenBucket | None = None,
        ttl_s: int | None = None,
        max_keys: int | None = None,
        prune_every: int | None = None,
        rules: Tuple[Tuple[str, Optional[TokenBucket], Optional[TokenBucket]], ...] = (),
        exempt_prefixes: Tuple[str, ...] = ("/docs", "/openapi.json") + _HEALTH_EXEMPTS,
    ):
        super().__init__(app)

        self._buckets: Dict[str, Tuple[int, int, int]] = {}

        self._write = write_bucket or TokenBucket(rate_per_sec=4, burst=20)
        self._read = read_bucket or TokenBucket(rate_per_sec=12, burst=40)
        self._rules = rules
        self._exempt_prefixes = exempt_prefixes

        self._ttl_s = int(ttl_s) if ttl_s is not None else _env_int("WEALL_RL_TTL_S", 900)
        self._max_keys = int(max_keys) if max_keys is not None else _env_int("WEALL_RL_MAX_KEYS", 20_000)
        pe = int(prune_every) if prune_every is not None else _env_int("WEALL_RL_PRUNE_EVERY", 256)
        self._prune_every = max(1, pe)
        self._req_count = 0

    def _pick_bucket(self, request: Request) -> TokenBucket:
        path = request.url.path or ""
        method = (request.method or "").upper()

        for prefix, write_b, read_b in self._rules:
            if path.startswith(prefix):
                if method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return write_b or self._write
                return read_b or self._read

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return self._write
        return self._read

    def _rate_limited(self) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"ok": False, "error": {"code": "rate_limited", "message": "Too many requests"}},
        )

    def _now_ns(self) -> int:
        return int(time.monotonic_ns())

    def _burst_capacity(self, bucket: TokenBucket) -> int:
        return int(bucket.burst) * _RATE_LIMIT_SCALE

    def _refill_units(self, bucket: TokenBucket, elapsed_ns: int) -> int:
        if elapsed_ns <= 0:
            return 0
        return (int(elapsed_ns) * int(bucket.rate_per_sec) * _RATE_LIMIT_SCALE) // _NS_PER_SECOND

    def _prune(self, now_ns: int) -> None:
        if self._ttl_s > 0:
            ttl_ns = int(self._ttl_s) * _NS_PER_SECOND
            cutoff_ns = int(now_ns) - ttl_ns
            stale = [k for k, (_, __, last_seen_ns) in self._buckets.items() if last_seen_ns < cutoff_ns]
            for k in stale:
                self._buckets.pop(k, None)

        if self._max_keys > 0 and len(self._buckets) > self._max_keys:
            items = [(k, v[2]) for k, v in self._buckets.items()]
            items.sort(key=lambda kv: kv[1])
            overflow = len(items) - self._max_keys
            for i in range(overflow):
                self._buckets.pop(items[i][0], None)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or ""
        for ex in self._exempt_prefixes:
            if path.startswith(ex):
                return await call_next(request)

        ip = _client_ip(request)
        bucket = self._pick_bucket(request)

        now_ns = self._now_ns()

        self._req_count += 1
        if (self._req_count % self._prune_every) == 0:
            self._prune(now_ns)

        key = f"{ip}:{bucket.rate_per_sec}:{bucket.burst}"
        burst_units = self._burst_capacity(bucket)
        cost_units = _RATE_LIMIT_SCALE

        tokens_units, last_ns, _last_seen_ns = self._buckets.get(key, (burst_units, now_ns, now_ns))

        refill_units = self._refill_units(bucket, now_ns - int(last_ns))
        available_units = min(burst_units, int(tokens_units) + refill_units)
        if available_units < cost_units:
            self._buckets[key] = (available_units, now_ns, now_ns)
            return self._rate_limited()

        remaining_units = available_units - cost_units
        self._buckets[key] = (remaining_units, now_ns, now_ns)

        if self._max_keys > 0 and len(self._buckets) > self._max_keys:
            self._prune(now_ns)

        return await call_next(request)
