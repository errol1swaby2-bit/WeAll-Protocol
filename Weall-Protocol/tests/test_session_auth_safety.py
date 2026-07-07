from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.mode_isolation import direct_session_mutation_issue
from weall.crypto.pq_mldsa import mldsa65_public_key_from_seed
from weall.crypto.sig import sign_mldsa

SESSION_LOGIN_PRIVKEY = "dcf7f9411aaf31d038f0cde1ac634ec77b23265ae6f6c4e43741d294414811a1"
SESSION_LOGIN_PUBKEY = mldsa65_public_key_from_seed(
    privkey=SESSION_LOGIN_PRIVKEY,
    encoding="hex",
)
from weall.runtime.apply.identity import apply_identity
from weall.runtime.session_keys import session_record_for, session_record_key
from weall.runtime.tx_admission_types import TxEnvelope

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = REPO_ROOT.parent


def _canon(account: str, session_key: str, ttl_s: int, issued_at_ms: int, device_id: str) -> bytes:
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
            "sig_profile": "pq-mldsa-v1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_prod_and_normal_dev_forbid_direct_session_mutation() -> None:
    assert (
        direct_session_mutation_issue({"WEALL_MODE": "prod"})
        == "direct_session_mutation_forbidden_in_production"
    )
    assert (
        direct_session_mutation_issue({"WEALL_MODE": "production_like"})
        == "direct_session_mutation_forbidden_in_production"
    )
    assert (
        direct_session_mutation_issue({"WEALL_MODE": "devnet"})
        == "direct_session_mutation_forbidden_in_controlled_devnet"
    )
    assert (
        direct_session_mutation_issue({"WEALL_MODE": "dev"})
        == "direct_session_mutation_forbidden_outside_seeded_demo"
    )
    assert (
        direct_session_mutation_issue(
            {
                "WEALL_MODE": "dev",
                "WEALL_RUNTIME_PROFILE": "seeded_demo",
                "WEALL_ENABLE_DEMO_SEED_ROUTE": "1",
                "WEALL_ALLOW_DIRECT_SESSION_MUTATION": "1",
            }
        )
        is None
    )


@pytest.mark.parametrize("path", ["/v1/session/create", "/v1/session/login"])
def test_prod_session_mutation_routes_forbidden(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_RUNTIME_PROFILE", raising=False)
    app = create_app(boot_runtime=False)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(path, json={"account": "@alice", "session_key": "sk"})
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "direct_session_mutation_forbidden_in_production"


def test_account_session_key_issue_stores_hash_and_revoke_accepts_raw_key() -> None:
    state = {
        "height": 7,
        "time": 1000,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "keys": {"by_id": {"k1": {"pubkey": "pk1", "revoked": False}}},
            }
        },
    }
    raw_key = "raw-browser-session-key"
    state = apply_identity(
        state,
        TxEnvelope(
            tx_type="ACCOUNT_SESSION_KEY_ISSUE",
            signer="@alice",
            nonce=1,
            payload={"session_key": raw_key, "ttl_s": 3600},
            tx_id="tx-issue",
        ),
    )
    sessions = state["accounts"]["@alice"]["session_keys"]
    assert raw_key not in sessions
    rec = session_record_for(sessions, raw_key)
    assert rec is not None
    assert rec["active"] is True
    assert session_record_key(raw_key) in sessions

    state = apply_identity(
        state,
        TxEnvelope(
            tx_type="ACCOUNT_SESSION_KEY_REVOKE",
            signer="@alice",
            nonce=2,
            payload={"session_key": raw_key},
            tx_id="tx-revoke",
        ),
    )
    assert session_record_for(state["accounts"]["@alice"]["session_keys"], raw_key)["active"] is False


def test_seeded_demo_direct_login_stores_hashed_session_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "seeded_demo")
    monkeypatch.setenv("WEALL_ENABLE_DEMO_SEED_ROUTE", "1")
    monkeypatch.setenv("WEALL_ALLOW_DIRECT_SESSION_MUTATION", "1")

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

    app = create_app(boot_runtime=False)
    client = TestClient(app, raise_server_exceptions=False)
    account = "@satoshi"
    session_key = base64.b64encode(b"y" * 32).decode()
    ttl_s = 3600
    issued_at_ms = state["time"] * 1000
    device_id = "browser:@satoshi:test"
    sig = sign_mldsa(
        message=_canon(account, session_key, ttl_s, issued_at_ms, device_id),
        privkey=SESSION_LOGIN_PRIVKEY,
        encoding="base64",
    )

    r = client.post(
        "/v1/session/login",
        json={
            "account": account,
            "session_key": session_key,
            "ttl_s": ttl_s,
            "issued_at_ms": issued_at_ms,
            "device_id": device_id,
            "pubkey": SESSION_LOGIN_PUBKEY,
            "sig": sig,
        },
    )
    assert r.status_code == 200, r.text
    sessions = state["accounts"][account]["session_keys"]
    assert session_key not in sessions
    assert sessions[session_record_key(session_key)]["active"] is True


def test_frontend_key_storage_never_writes_secret_to_localstorage() -> None:
    text = (OUTER_ROOT / "web/src/auth/keys.ts").read_text(encoding="utf-8")
    assert "KEYRING_PREFIX" not in text
    assert "localStorage.setItem(`${KEYRING_PREFIX}${normalized}`" not in text
    assert "secretKey: secretKeyB64" not in text
    assert "secretKeyB64," not in text.split("export function saveKeypair", 1)[1].split("export function loadKeypair", 1)[0]
    assert "sessionStorage.setItem(secretStorageKey(normalized), secretKeyB64)" in text


def test_frontend_logout_revokes_and_clears_local_state() -> None:
    text = (OUTER_ROOT / "web/src/auth/session.ts").read_text(encoding="utf-8")
    assert "export async function logoutCurrentDevice" in text
    logout_block = text.split("export async function logoutCurrentDevice", 1)[1].split("export async function issueFreshSessionKey", 1)[0]
    assert "revokeCurrentSessionKey" in logout_block
    assert "endSession()" in logout_block
    assert "clearNonceReservation(account)" in logout_block
    assert "clearSignerLock(account)" in logout_block

    page = (OUTER_ROOT / "web/src/pages/SessionDevicesPage.tsx").read_text(encoding="utf-8")
    assert "logoutCurrentDevice" in page
    assert "Log out of this device" in page
