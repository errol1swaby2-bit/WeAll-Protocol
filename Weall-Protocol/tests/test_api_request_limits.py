from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


def test_request_size_limit_returns_413(monkeypatch):
    # Make limit very small for test determinism.
    monkeypatch.setenv("WEALL_MAX_REQUEST_BYTES", "128")
    monkeypatch.delenv("WEALL_MAX_JSON_BYTES", raising=False)
    monkeypatch.delenv("WEALL_SIZE_LIMIT_DISABLE", raising=False)

    app = create_app(boot_runtime=False)
    c = TestClient(app)

    # A POST endpoint that exists in the public router.
    # We use /v1/poh/email/start because it is present and expects JSON.
    payload = {"account": "@alice", "email": "a@b.com", "pad": "x" * 500}

    r = c.post("/v1/poh/email/start", json=payload)
    assert r.status_code == 413

    j = r.json()
    assert j.get("ok") is False
    assert isinstance(j.get("error"), dict)
    assert j["error"].get("code") == "tx_too_large"
