from __future__ import annotations

import time

import pytest

from weall.poh.operator_email_receipts import canonical_receipt_message, canonical_relay_token_message
from weall.runtime.apply.poh import apply_poh_email_receipt_submit
from weall.runtime.errors import ApplyError
from weall.testing.sigtools import deterministic_ed25519_keypair


def _base_state() -> dict:
    return {
        "chain_id": "test",
        "height": 0,
        "accounts": {},
        "roles": {"node_operators": {"by_id": {}, "active_set": []}},
        "poh": {},
        "poh_nfts": {"by_id": {}, "by_owner": {}},
    }


def _register_account(state: dict, account_id: str, pubkey: str, *, tier: int = 0, reputation: float = 0.0) -> None:
    state["accounts"][account_id] = {
        "account_id": account_id,
        "poh_tier": tier,
        "reputation": reputation,
        "banned": False,
        "locked": False,
        "keys": {"by_id": {f"kid:{account_id}": {"pubkey": pubkey, "revoked": False}}},
    }


def _activate_operator(state: dict, account_id: str) -> None:
    ops = state["roles"]["node_operators"]
    ops["by_id"][account_id] = {"account_id": account_id, "enrolled": True, "active": True, "enrolled_at_nonce": 1, "activated_at_nonce": 2}
    ops["active_set"] = sorted(set(list(ops.get("active_set") or []) + [account_id]))


def _make_relay_token(*, relay_account_id: str, relay_pubkey: str, relay_privkey, subject_account_id: str, operator_account_id: str) -> dict:
    now = int(time.time() * 1000)
    payload = {
        "version": 1,
        "type": "email_challenge_completed",
        "challenge_id": "challenge:demo",
        "account_id": subject_account_id,
        "operator_account_id": operator_account_id,
        "email_commitment": "sha256:demo",
        "issued_at_ms": now,
        "expires_at_ms": now + 60_000,
        "relay_account_id": relay_account_id,
        "relay_pubkey": relay_pubkey,
    }
    return {"payload": payload, "signature": relay_privkey.sign(canonical_relay_token_message(payload)).hex()}


def _make_receipt(*, worker_account_id: str, worker_pubkey: str, worker_privkey, subject_account_id: str, relay_token: dict) -> dict:
    rp = relay_token["payload"]
    receipt = {
        "version": 1,
        "kind": "poh_email_tier1",
        "worker_account_id": worker_account_id,
        "worker_pubkey": worker_pubkey,
        "subject_account_id": subject_account_id,
        "email_commitment": rp["email_commitment"],
        "request_id": rp["challenge_id"],
        "nonce": relay_token["signature"],
        "issued_at_ms": rp["issued_at_ms"],
        "expires_at_ms": rp["expires_at_ms"],
        "relay_token": relay_token,
    }
    receipt["signature"] = worker_privkey.sign(canonical_receipt_message(receipt)).hex()
    return receipt


def test_operator_signed_email_receipt_grants_tier1(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _base_state()
    rpub, rsk = deterministic_ed25519_keypair(label="@relay")
    wpub, wsk = deterministic_ed25519_keypair(label="@worker")
    spub, _ = deterministic_ed25519_keypair(label="@subject")
    monkeypatch.setenv("WEALL_EMAIL_RELAY_ACCOUNT_ID", "@relay")
    monkeypatch.setenv("WEALL_EMAIL_RELAY_PUBKEY", rpub)
    _register_account(state, "@worker", wpub, tier=3, reputation=1.0)
    _register_account(state, "@subject", spub, tier=0, reputation=0.0)
    _activate_operator(state, "@worker")
    relay_token = _make_relay_token(relay_account_id="@relay", relay_pubkey=rpub, relay_privkey=rsk, subject_account_id="@subject", operator_account_id="@worker")
    receipt = _make_receipt(worker_account_id="@worker", worker_pubkey=wpub, worker_privkey=wsk, subject_account_id="@subject", relay_token=relay_token)
    out = apply_poh_email_receipt_submit(state, {"payload": {"account_id": "@subject", "receipt": receipt}, "signer": "@subject"})
    assert out["applied"] == "POH_EMAIL_RECEIPT_SUBMIT"
    assert int(state["accounts"]["@subject"]["poh_tier"]) == 1
    with pytest.raises(ApplyError) as ei:
        apply_poh_email_receipt_submit(state, {"payload": {"account_id": "@subject", "receipt": receipt}, "signer": "@subject"})
    assert ei.value.reason == "receipt_replayed"


def test_bad_relay_signature_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _base_state()
    rpub, rsk = deterministic_ed25519_keypair(label="@relay")
    wpub, wsk = deterministic_ed25519_keypair(label="@worker")
    spub, _ = deterministic_ed25519_keypair(label="@subject")
    monkeypatch.setenv("WEALL_EMAIL_RELAY_ACCOUNT_ID", "@relay")
    monkeypatch.setenv("WEALL_EMAIL_RELAY_PUBKEY", rpub)
    _register_account(state, "@worker", wpub, tier=3, reputation=1.0)
    _register_account(state, "@subject", spub, tier=0, reputation=0.0)
    _activate_operator(state, "@worker")
    relay_token = _make_relay_token(relay_account_id="@relay", relay_pubkey=rpub, relay_privkey=rsk, subject_account_id="@subject", operator_account_id="@worker")
    relay_token["signature"] = "00" * 64
    receipt = _make_receipt(worker_account_id="@worker", worker_pubkey=wpub, worker_privkey=wsk, subject_account_id="@subject", relay_token=relay_token)
    with pytest.raises(ApplyError) as ei:
        apply_poh_email_receipt_submit(state, {"payload": {"account_id": "@subject", "receipt": receipt}, "signer": "@subject"})
    assert ei.value.reason == "bad_relay_signature"
