from __future__ import annotations

import hashlib
import socket
import smtplib
import time

from weall.runtime.apply.poh import apply_poh_email_attestation_submit
from weall.runtime.poh.email_attestation import (
    build_unsigned_email_control_attestation_v1,
    domain_hash_for_attestation,
    email_hash_for_attestation,
    sign_email_control_attestation_v1,
)
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_hex(label: str) -> str:
    return hashlib.sha256(("weall-test-ed25519:" + label).encode("utf-8")).hexdigest()


def _state() -> dict:
    op_pub, _ = deterministic_ed25519_keypair(label="@oracle")
    user_pub, _ = deterministic_ed25519_keypair(label="@alice")
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "@alice": {"account_id": "@alice", "poh_tier": 0, "banned": False, "locked": False, "keys": {"by_id": {"k1": {"pubkey": user_pub, "revoked": False}}}},
            "@oracle": {"account_id": "@oracle", "poh_tier": 3, "banned": False, "locked": False, "keys": {"by_id": {"k1": {"pubkey": op_pub, "revoked": False}}}},
        },
        "oracle_registry": {"oracles": {"oracle:poh-email:1": {"oracle_id": "oracle:poh-email:1", "operator_account": "@oracle", "oracle_type": "poh_email_tier1", "oracle_pubkey": op_pub, "status": "active", "registered_at_height": 1, "valid_from_height": 1}}},
        "poh": {},
        "poh_nfts": {"by_id": {}, "by_owner": {}},
    }


def _attestation() -> dict:
    email_hash = email_hash_for_attestation(normalized_email="alice@example.org", salt="test-salt", account_id="@alice")
    domain_hash = domain_hash_for_attestation(normalized_email="alice@example.org", salt="test-salt", account_id="@alice")
    unsigned = build_unsigned_email_control_attestation_v1(chain_id="weall-test", account_id="@alice", email_hash=email_hash, domain_hash=domain_hash, challenge_id="challenge:1", issued_at_height=5, expires_at_height=20, oracle_id="oracle:poh-email:1")
    return sign_email_control_attestation_v1(unsigned, oracle_private_key=_seed_hex("@oracle"))


def test_attestation_execution_does_not_call_wall_clock_smtp_or_network(monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("external side effect called during deterministic execution")

    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(smtplib, "SMTP", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    state = _state()
    out = apply_poh_email_attestation_submit(
        state,
        {"tx_type": "POH_EMAIL_ATTESTATION_SUBMIT", "signer": "@alice", "nonce": 1, "payload": {"account_id": "@alice", "attestation": _attestation()}},
    )

    assert out["applied"] == "POH_EMAIL_ATTESTATION_SUBMIT"
    assert state["accounts"]["@alice"]["poh_tier"] == 1
