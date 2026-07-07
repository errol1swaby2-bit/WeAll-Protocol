from __future__ import annotations

import base64
import json
import time

from fastapi.testclient import TestClient

from weall.api.app import app
from weall.crypto.pq_mldsa import generate_mldsa65_keypair, sign_mldsa65
from weall.runtime.session_keys import session_record_key


def _canon(
    account: str,
    session_key: str,
    ttl_s: int,
    issued_at_ms: int,
    device_id: str,
    *,
    sig_profile: str,
    chain_id: str,
    network_id: str,
) -> bytes:
    return json.dumps(
        {
            "t": "SESSION_LOGIN",
            "account": account,
            "session_key": session_key,
            "ttl_s": ttl_s,
            "issued_at_ms": issued_at_ms,
            "device_id": device_id,
            "domain_separator": "weall.session.login.v1",
            "object_kind": "session_login",
            "sig_profile": sig_profile,
            "chain_id": chain_id,
            "network_id": network_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_session_login_accepts_pq_mldsa_profile_under_strict_crypto_mode(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "demo")
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "controlled-testnet")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "seeded_demo")
    monkeypatch.setenv("WEALL_ENABLE_DEMO_SEED_ROUTE", "1")
    monkeypatch.setenv("WEALL_ALLOW_DIRECT_SESSION_MUTATION", "1")
    client = TestClient(app)
    from weall.api.routes_public_parts import common

    kp = generate_mldsa65_keypair()
    account = "@satoshi"
    chain_id = "weall-testnet-v1"
    network_id = "weall-public-observer-testnet-v1"
    state = {
        "height": 0,
        "time": int(time.time()),
        "meta": {"chain_id": chain_id, "network_id": network_id},
        "accounts": {
            account: {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "keys": {
                    "by_id": {
                        "k:pq": {
                            "key_type": "main",
                            "sig_profile": "pq-mldsa-v1",
                            "pubkeys": {"mldsa": kp["pubkey"]},
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

    session_key = base64.b64encode(b"p" * 32).decode()
    ttl_s = 3600
    issued_at_ms = state["time"] * 1000
    device_id = "browser:@satoshi:pq"
    msg = _canon(
        account,
        session_key,
        ttl_s,
        issued_at_ms,
        device_id,
        sig_profile="pq-mldsa-v1",
        chain_id=chain_id,
        network_id=network_id,
    )
    sig = sign_mldsa65(message=msg, privkey=kp["privkey"], encoding="hex")

    r = client.post(
        "/v1/session/login",
        json={
            "account": account,
            "session_key": session_key,
            "ttl_s": ttl_s,
            "issued_at_ms": issued_at_ms,
            "device_id": device_id,
            "sig_profile": "pq-mldsa-v1",
            "pubkey": kp["pubkey"],
            "sig": sig,
        },
    )
    assert r.status_code == 200, r.text
    assert state["accounts"][account]["session_keys"][session_record_key(session_key)]["sig_profile"] == "pq-mldsa-v1"
    assert state["accounts"][account]["devices"]["by_id"][device_id]["sig_profile"] == "pq-mldsa-v1"


def test_session_login_rejects_missing_profile_under_strict_crypto_mode(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "demo")
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "controlled-testnet")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "seeded_demo")
    monkeypatch.setenv("WEALL_ENABLE_DEMO_SEED_ROUTE", "1")
    monkeypatch.setenv("WEALL_ALLOW_DIRECT_SESSION_MUTATION", "1")
    client = TestClient(app)
    from weall.api.routes_public_parts import common

    state = {
        "height": 0,
        "time": int(time.time()),
        "meta": {"chain_id": "weall-testnet-v1", "network_id": "weall-public-observer-testnet-v1"},
        "accounts": {"@satoshi": {"keys": {"by_id": {}}, "devices": {"by_id": {}}, "session_keys": {}}},
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

    r = client.post(
        "/v1/session/login",
        json={
            "account": "@satoshi",
            "session_key": base64.b64encode(b"q" * 32).decode(),
            "ttl_s": 3600,
            "issued_at_ms": state["time"] * 1000,
            "device_id": "browser:@satoshi:missing-profile",
            "pubkey": "00",
            "sig": "00",
        },
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "sig_profile_required"
