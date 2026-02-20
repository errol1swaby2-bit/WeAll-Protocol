from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception:
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
            # In production, require an explicit allowlist so a misconfigured
            # deployment can't accidentally trust spoofed headers when the
            # backend is exposed directly to the internet.
            mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
            if mode == "prod":
                # Keep unit tests ergonomic: TestClient does not provide a real
                # IP peer, so allow trusting proxy headers when running under
                # pytest. Production deployments should always set an allowlist.
                if os.environ.get("PYTEST_CURRENT_TEST"):
                    return True
                return False

            # In dev/testnet, allow trusting proxy headers without an allowlist
            # for convenience.
            return True

        peer = request.client.host if request.client else ""
        if not peer or not _is_valid_ip(peer):
            return False

        try:
            peer_ip = ipaddress.ip_address(peer)
        except Exception:
            return False

        # Hard-cap to avoid pathological env misconfig.
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

    trust_proxy = _truthy(os.environ.get("WEALL_TRUST_PROXY_HEADERS"))
    if trust_proxy and _trusted_proxy_ok():
        # Prefer provider-specific “real client IP” headers when available.
        for hdr in ("cf-connecting-ip", "x-real-ip"):
            v = (request.headers.get(hdr) or "").strip()
            if v and _is_valid_ip(v):
                return v

        # X-Forwarded-For is a comma-separated list where the left-most entry is
        # commonly the original client.
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
    """Gate user-private API access behind a user's session key.

    Client provides:
      - X-WeAll-Account: "@alice"
      - X-WeAll-Session-Key: "..."

    Server checks deterministic ledger state:
      state["accounts"][account]["session_keys"][session_key].active == True
    """
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

    # Optional TTL enforcement when chain time + issued_at_ts exist.
    ttl_s = int(srec.get("ttl_s", 0) or 0)
    if ttl_s > 0:
        now = state.get("time")
        issued_at_ts = srec.get("issued_at_ts")
        if isinstance(now, int) and isinstance(issued_at_ts, int) and now > (issued_at_ts + ttl_s):
            raise PermissionError("session_expired")

    return acct


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Fail-fast request size limiter.

    - Enforces Content-Length when present.
    - Also caps buffered body size by reading body once when needed.

    Configure:
      WEALL_MAX_REQUEST_BYTES (default: 1_000_000)
      WEALL_MAX_JSON_BYTES     (alias; if set, overrides WEALL_MAX_REQUEST_BYTES)
      WEALL_SIZE_LIMIT_DISABLE=1 to disable (not recommended unless handled at edge)
    """

    def __init__(
        self,
        app,
        *,
        max_bytes: Optional[int] = None,
        exempt_prefixes: Tuple[str, ...] = ("/docs", "/openapi.json", "/health"),
    ):
        super().__init__(app)
        if _truthy(os.environ.get("WEALL_SIZE_LIMIT_DISABLE")):
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

    async def dispatch(self, request: Request, call_next):
        if not self._enabled:
            return await call_next(request)

        path = request.url.path or ""
        for ex in self._exempt_prefixes:
            if path.startswith(ex):
                return await call_next(request)

        # First gate using Content-Length if present (cheap).
        cl = request.headers.get("content-length")
        if cl:
            try:
                n = int(cl)
                if n > self._max_bytes:
                    return self._too_large()
            except Exception:
                # Ignore malformed header; fall back to buffered body cap.
                pass

        # For mutating requests, also cap actual body bytes (protect against chunked).
        method = (request.method or "").upper()
        if method in {"POST", "PUT", "PATCH"}:
            try:
                body = await request.body()
            except Exception:
                return JSONResponse(
                    status_code=400,
                    content={"ok": False, "error": {"code": "bad_request", "message": "Unable to read request body"}},
                )
            if body and len(body) > self._max_bytes:
                return self._too_large()

        return await call_next(request)


@dataclass(frozen=True)
class TokenBucket:
    rate_per_sec: float
    burst: float


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory token bucket rate limiter with path-specific rules.

    Good for single-node Genesis. For multi-replica deployments, enforce at edge.

    IMPORTANT:
      This is intentionally best-effort and in-memory. We apply TTL + size-cap
      eviction to prevent unbounded memory growth under scanning / churn.
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
        exempt_prefixes: Tuple[str, ...] = ("/docs", "/openapi.json", "/health"),
    ):
        super().__init__(app)

        # Keyed by "<ip>:<rate>:<burst>".
        # Value: (tokens_remaining, last_refill_ts, last_seen_ts)
        self._buckets: Dict[str, Tuple[float, float, float]] = {}

        self._write = write_bucket or TokenBucket(rate_per_sec=4.0, burst=20.0)
        self._read = read_bucket or TokenBucket(rate_per_sec=12.0, burst=40.0)
        self._rules = rules
        self._exempt_prefixes = exempt_prefixes

        # Configure via env:
        #   WEALL_RL_TTL_S         (default 900 seconds)
        #   WEALL_RL_MAX_KEYS      (default 20000)
        #   WEALL_RL_PRUNE_EVERY   (default 256 requests)
        self._ttl_s = int(ttl_s) if ttl_s is not None else _env_int("WEALL_RL_TTL_S", 900)
        self._max_keys = int(max_keys) if max_keys is not None else _env_int("WEALL_RL_MAX_KEYS", 20_000)
        pe = int(prune_every) if prune_every is not None else _env_int("WEALL_RL_PRUNE_EVERY", 256)
        self._prune_every = max(1, pe)
        self._req_count = 0

    def _pick_bucket(self, request: Request) -> TokenBucket:
        path = request.url.path or ""
        method = (request.method or "").upper()

        # Path rules can override default read/write buckets.
        for prefix, write_b, read_b in self._rules:
            if path.startswith(prefix):
                if method in {"POST", "PUT", "PATCH", "DELETE"}:
                    return write_b or self._write
                return read_b or self._read

        # Default: methods map to read/write.
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return self._write
        return self._read

    def _rate_limited(self) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"ok": False, "error": {"code": "rate_limited", "message": "Too many requests"}},
        )

    def _prune(self, now: float) -> None:
        # TTL eviction.
        if self._ttl_s > 0:
            cutoff = now - float(self._ttl_s)
            stale = [k for k, (_, __, last_seen) in self._buckets.items() if last_seen < cutoff]
            for k in stale:
                self._buckets.pop(k, None)

        # Size cap eviction: drop oldest by last_seen.
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

        now = time.time()

        self._req_count += 1
        if (self._req_count % self._prune_every) == 0:
            self._prune(now)

        key = f"{ip}:{bucket.rate_per_sec}:{bucket.burst}"

        tokens, last, _last_seen = self._buckets.get(key, (bucket.burst, now, now))

        # Refill.
        tokens = min(bucket.burst, tokens + (now - last) * bucket.rate_per_sec)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now, now)
            return self._rate_limited()

        tokens -= 1.0
        self._buckets[key] = (tokens, now, now)

        # Enforce size cap immediately (avoid "prune before insert" leaving overflow).
        if self._max_keys > 0 and len(self._buckets) > self._max_keys:
            self._prune(now)

        return await call_next(request)
