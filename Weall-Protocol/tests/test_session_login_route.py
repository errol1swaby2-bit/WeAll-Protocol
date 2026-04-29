from __future__ import annotations

import base64
import json
import time

from fastapi.testclient import TestClient

from weall.api.app import app
from weall.crypto.sig import sign_ed25519


def _canon(account: str, session_key: str, ttl_s: int, issued_at_ms: int, device_id: str) -> bytes:
    return json.dumps(
        {
            "t": "SESSION_LOGIN",
            "account": account,
            "session_key": session_key,
            "ttl_s": ttl_s,
            "issued_at_ms": issued_at_ms,
            "device_id": device_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_session_login_creates_device_and_session(monkeypatch):
    client = TestClient(app)
    from weall.api.routes_public_parts import common

    state = {
        "height": 0,
        "time": int(time.time()),
        "accounts": {
            "@satoshi": {
                "nonce": 0,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "keys": {
                    "by_id": {
                        "k:1": {
                            "key_type": "main",
                            "pubkey": "15c57e17e48ac97cb24538397f2402e3776f1ad1b756ab40af4dfd66db4f5e19",
                            "revoked": False,
                            "revoked_at": None,
                        }
                    }
                },
                "devices": {"by_id": {}},
                "session_keys": {},
            }
        },
    }

    class Store:
        def update(self, fn):
            fn(state)

    class Ex:
        _ledger_store = Store()
        def read_state(self):
            return state

    monkeypatch.setattr(common, "_executor", lambda request: Ex())
    monkeypatch.setattr(common, "_snapshot", lambda request: state)

    account = "@satoshi"
    session_key = base64.b64encode(b"x" * 32).decode()
    ttl_s = 3600
    issued_at_ms = state["time"] * 1000
    device_id = "browser:@satoshi:test"
    msg = _canon(account, session_key, ttl_s, issued_at_ms, device_id)
    sig = sign_ed25519(message=msg, privkey="dcf7f9411aaf31d038f0cde1ac634ec77b23265ae6f6c4e43741d294414811a1", encoding="base64")

    r = client.post("/v1/session/login", json={
        "account": account,
        "session_key": session_key,
        "ttl_s": ttl_s,
        "issued_at_ms": issued_at_ms,
        "device_id": device_id,
        "pubkey": "15c57e17e48ac97cb24538397f2402e3776f1ad1b756ab40af4dfd66db4f5e19",
        "sig": sig,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert state["accounts"][account]["session_keys"][session_key]["active"] is True
    assert device_id in state["accounts"][account]["devices"]["by_id"]
