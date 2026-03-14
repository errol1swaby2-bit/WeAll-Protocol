from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _find_rate_limit_instance(app: FastAPI):
    """Walk the middleware stack to find the live RateLimitMiddleware instance."""

    cur = app.middleware_stack
    while cur is not None:
        if cur.__class__.__name__ == "RateLimitMiddleware":
            return cur
        cur = getattr(cur, "app", None)
    return None


def test_rate_limit_prunes_by_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """TTL eviction prevents unbounded key growth under churn."""

    from weall.api.security import RateLimitMiddleware
    import weall.api.security as sec

    # Force proxy header trust so we can fake per-request IPs.
    monkeypatch.setenv("WEALL_TRUST_PROXY_HEADERS", "1")
    monkeypatch.delenv("WEALL_TRUSTED_PROXY_IPS", raising=False)

    t = 1_000.0

    def _now() -> float:
        return float(t)

    # Monkeypatch module time used by the middleware.
    monkeypatch.setattr(sec.time, "time", _now)

    app = FastAPI()

    @app.get("/ping")
    def _ping():
        return {"ok": True}

    # Very small TTL and frequent pruning for determinism.
    app.add_middleware(RateLimitMiddleware, ttl_s=10, max_keys=1000, prune_every=1)

    with TestClient(app) as client:
        # Create many buckets.
        for i in range(50):
            r = client.get("/ping", headers={"x-forwarded-for": f"203.0.113.{i}"})
            assert r.status_code == 200

        rl = _find_rate_limit_instance(app)
        assert rl is not None

        before = len(rl._buckets)
        assert before >= 50

        # Advance beyond TTL for all existing keys.
        t += 60.0

        # One more request triggers prune_every=1.
        r = client.get("/ping", headers={"x-forwarded-for": "203.0.113.250"})
        assert r.status_code == 200

        after = len(rl._buckets)
        assert after < before
        # Typically only the new key remains.
        assert after <= 5


def test_rate_limit_prunes_by_max_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Size-cap eviction drops oldest keys when max_keys is exceeded."""

    from weall.api.security import RateLimitMiddleware
    import weall.api.security as sec

    monkeypatch.setenv("WEALL_TRUST_PROXY_HEADERS", "1")
    monkeypatch.delenv("WEALL_TRUSTED_PROXY_IPS", raising=False)

    t = 5_000.0

    def _now() -> float:
        return float(t)

    monkeypatch.setattr(sec.time, "time", _now)

    app = FastAPI()

    @app.get("/ping")
    def _ping():
        return {"ok": True}

    app.add_middleware(RateLimitMiddleware, ttl_s=0, max_keys=3, prune_every=1)

    with TestClient(app) as client:
        # Touch 4 distinct keys, forcing eviction down to 3.
        for i in range(4):
            t += 1.0
            r = client.get("/ping", headers={"x-forwarded-for": f"198.51.100.{i}"})
            assert r.status_code == 200

        rl = _find_rate_limit_instance(app)
        assert rl is not None

        assert len(rl._buckets) == 3
