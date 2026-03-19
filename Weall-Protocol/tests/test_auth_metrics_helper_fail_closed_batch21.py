import pytest


def test_metrics_enabled_invalid_boolean_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_METRICS_ENABLED", "maybe")
    from weall.runtime import metrics as mod

    with pytest.raises(ValueError, match="invalid_boolean_env:WEALL_METRICS_ENABLED"):
        mod.metrics_enabled()


def test_trust_proxy_headers_invalid_boolean_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_TRUST_PROXY_HEADERS", "maybe")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from weall.api.security import RateLimitMiddleware

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.get("/x")
    def _x():
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/x")
    assert resp.status_code == 500


def test_size_limit_disable_invalid_boolean_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIZE_LIMIT_DISABLE", "maybe")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from weall.api.security import RequestSizeLimitMiddleware

    app = FastAPI()
    app.add_middleware(RequestSizeLimitMiddleware)

    @app.post("/x")
    async def _x():
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/x", json={"ok": True})
    assert resp.status_code == 500


def test_invalid_boolean_envs_remain_permissive_in_test_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_METRICS_ENABLED", "maybe")
    monkeypatch.setenv("WEALL_TRUST_PROXY_HEADERS", "maybe")
    monkeypatch.setenv("WEALL_SIZE_LIMIT_DISABLE", "maybe")

    from weall.runtime import metrics as metrics_mod
    from weall.api.security import _env_bool as security_env_bool

    assert metrics_mod.metrics_enabled() is False
    assert security_env_bool("WEALL_TRUST_PROXY_HEADERS", False) is False
    assert security_env_bool("WEALL_SIZE_LIMIT_DISABLE", False) is False
