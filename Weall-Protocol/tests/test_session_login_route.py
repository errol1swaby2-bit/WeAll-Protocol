from __future__ import annotations

import base64
import json
import time

from fastapi.testclient import TestClient

from weall.api.app import app
from weall.crypto.pq_mldsa import mldsa65_public_key_from_seed
from weall.crypto.sig import sign_mldsa

SESSION_LOGIN_PRIVKEY = "dcf7f9411aaf31d038f0cde1ac634ec77b23265ae6f6c4e43741d294414811a1"
SESSION_LOGIN_PUBKEY = mldsa65_public_key_from_seed(
    privkey=SESSION_LOGIN_PRIVKEY,
    encoding="hex",
)
from weall.runtime.session_keys import session_record_key


def _canon(
    account: str,
    session_key: str,
    ttl_s: int,
    issued_at_ms: int,
    device_id: str,
    *,
    chain_id: str = "",
    network_id: str = "",
) -> bytes:
    payload = {
        "t": "SESSION_LOGIN",
        "account": account,
        "session_key": session_key,
        "ttl_s": ttl_s,
        "issued_at_ms": issued_at_ms,
        "device_id": device_id,
        "domain_separator": "weall.session.login.v1",
        "object_kind": "session_login",
        "sig_profile": "pq-mldsa-v1",
    }
    if chain_id:
        payload["chain_id"] = chain_id
    if network_id:
        payload["network_id"] = network_id
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_session_login_creates_device_and_session(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "seeded_demo")
    monkeypatch.setenv("WEALL_ENABLE_DEMO_SEED_ROUTE", "1")
    monkeypatch.setenv("WEALL_ALLOW_DIRECT_SESSION_MUTATION", "1")
    client = TestClient(app)
    from weall.api.routes_public_parts import common

    state = {
        "height": 0,
        "time": int(time.time()),
        "accounts": {
            "@satoshi": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "keys": {
                    "by_id": {
                        "k:1": {
                            "key_type": "main",
                            "pubkey": SESSION_LOGIN_PUBKEY,
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
    sig = sign_mldsa(message=msg, privkey=SESSION_LOGIN_PRIVKEY, encoding="base64")

    r = client.post("/v1/session/login", json={
        "account": account,
        "session_key": session_key,
        "ttl_s": ttl_s,
        "issued_at_ms": issued_at_ms,
        "device_id": device_id,
        "pubkey": SESSION_LOGIN_PUBKEY,
        "sig": sig,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert session_key not in state["accounts"][account]["session_keys"]
    assert state["accounts"][account]["session_keys"][session_record_key(session_key)]["active"] is True
    assert device_id in state["accounts"][account]["devices"]["by_id"]


def test_session_login_uses_top_level_state_chain_id_for_signature_domain(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "seeded_demo")
    monkeypatch.setenv("WEALL_ENABLE_DEMO_SEED_ROUTE", "1")
    monkeypatch.setenv("WEALL_ALLOW_DIRECT_SESSION_MUTATION", "1")
    client = TestClient(app)
    from weall.api.routes_public_parts import common

    state = {
        "height": 0,
        "time": int(time.time()),
        "chain_id": "weall-controlled-devnet",
        "accounts": {
            "@devnet-genesis": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "keys": {
                    "by_id": {
                        "k:genesis": {
                            "key_type": "main",
                            "pubkey": SESSION_LOGIN_PUBKEY,
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

    account = "@devnet-genesis"
    session_key = base64.b64encode(b"g" * 32).decode()
    ttl_s = 3600
    issued_at_ms = state["time"] * 1000
    device_id = "browser:@devnet-genesis:test"
    sig = sign_mldsa(
        message=_canon(
            account,
            session_key,
            ttl_s,
            issued_at_ms,
            device_id,
            chain_id="weall-controlled-devnet",
        ),
        privkey=SESSION_LOGIN_PRIVKEY,
        encoding="base64",
    )

    r = client.post("/v1/session/login", json={
        "account": account,
        "session_key": session_key,
        "ttl_s": ttl_s,
        "issued_at_ms": issued_at_ms,
        "device_id": device_id,
        "sig_profile": "pq-mldsa-v1",
        "pubkey": SESSION_LOGIN_PUBKEY,
        "sig": sig,
    })
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert state["accounts"][account]["session_keys"][session_record_key(session_key)]["active"] is True


def test_session_login_rejects_direct_session_mutation_in_controlled_devnet(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "devnet")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "controlled_devnet")
    monkeypatch.setenv("WEALL_ALLOW_DIRECT_SESSION_MUTATION", "1")
    client = TestClient(app)
    from weall.api.routes_public_parts import common

    state = {
        "height": 0,
        "time": int(time.time()),
        "chain_id": "weall-controlled-devnet",
        "accounts": {
            "@devnet-genesis": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "keys": {
                    "by_id": {
                        "k:genesis": {
                            "key_type": "main",
                            "pubkey": SESSION_LOGIN_PUBKEY,
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

    account = "@devnet-genesis"
    session_key = base64.b64encode(b"z" * 32).decode()
    ttl_s = 3600
    issued_at_ms = state["time"] * 1000
    device_id = "browser:@devnet-genesis:controlled-devnet"

    sig = sign_mldsa(
        message=_canon(
            account,
            session_key,
            ttl_s,
            issued_at_ms,
            device_id,
            chain_id="weall-controlled-devnet",
        ),
        privkey=SESSION_LOGIN_PRIVKEY,
        encoding="base64",
    )

    r = client.post("/v1/session/login", json={
        "account": account,
        "session_key": session_key,
        "ttl_s": ttl_s,
        "issued_at_ms": issued_at_ms,
        "device_id": device_id,
        "sig_profile": "pq-mldsa-v1",
        "pubkey": SESSION_LOGIN_PUBKEY,
        "sig": sig,
    })

    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "direct_session_mutation_forbidden_in_controlled_devnet"
