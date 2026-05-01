from __future__ import annotations

import hashlib

import pytest

from weall.runtime.apply.poh import apply_poh_email_attestation_submit
from weall.runtime.errors import ApplyError
from weall.runtime.poh.email_attestation import (
    build_unsigned_email_control_attestation_v1,
    domain_hash_for_attestation,
    email_hash_for_attestation,
    sign_email_control_attestation_v1,
)
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_hex(label: str) -> str:
    return hashlib.sha256(("weall-test-ed25519:" + label).encode("utf-8")).hexdigest()


def _base_state() -> dict:
    op_pub, _ = deterministic_ed25519_keypair(label="@oracle")
    user_pub, _ = deterministic_ed25519_keypair(label="@alice")
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "@alice": {
                "account_id": "@alice",
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "keys": {"by_id": {"k1": {"pubkey": user_pub, "revoked": False}}},
            },
            "@oracle": {
                "account_id": "@oracle",
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "keys": {"by_id": {"k1": {"pubkey": op_pub, "revoked": False}}},
            },
        },
        "oracle_registry": {
            "oracles": {
                "oracle:poh-email:1": {
                    "oracle_id": "oracle:poh-email:1",
                    "operator_account": "@oracle",
                    "oracle_type": "poh_email_tier1",
                    "oracle_pubkey": op_pub,
                    "status": "active",
                    "endpoint_commitment": "sha256:endpoint",
                    "mail_domain_hash": "sha256:domain",
                    "registered_at_height": 1,
                    "suspended_at_height": None,
                    "rotated_from_oracle_id": None,
                    "valid_from_height": 1,
                    "valid_until_height": None,
                }
            }
        },
        "poh": {},
        "poh_nfts": {"by_id": {}, "by_owner": {}},
    }


def _attestation(challenge_id: str = "challenge:1") -> dict:
    email_hash = email_hash_for_attestation(
        normalized_email="alice@example.org",
        salt="test-salt",
        account_id="@alice",
    )
    domain_hash = domain_hash_for_attestation(
        normalized_email="alice@example.org",
        salt="test-salt",
        account_id="@alice",
    )
    unsigned = build_unsigned_email_control_attestation_v1(
        chain_id="weall-test",
        account_id="@alice",
        email_hash=email_hash,
        domain_hash=domain_hash,
        challenge_id=challenge_id,
        issued_at_height=5,
        expires_at_height=20,
        oracle_id="oracle:poh-email:1",
    )
    return sign_email_control_attestation_v1(unsigned, oracle_private_key=_seed_hex("@oracle"))


def _env(attestation: dict, *, signer: str = "@alice") -> dict:
    return {
        "tx_type": "POH_EMAIL_ATTESTATION_SUBMIT",
        "signer": signer,
        "nonce": 1,
        "payload": {"account_id": "@alice", "attestation": attestation},
    }


def test_poh_email_attestation_submit_grants_canonical_tier1() -> None:
    state = _base_state()
    out = apply_poh_email_attestation_submit(state, _env(_attestation()))

    assert out["applied"] == "POH_EMAIL_ATTESTATION_SUBMIT"
    assert state["accounts"]["@alice"]["poh_tier"] == 1
    status = state["poh"]["account_status"]["@alice"]
    assert status["poh_tier"] == 1
    assert status["status"] == "active"
    assert status["issuer_oracle_id"] == "oracle:poh-email:1"
    assert "alice@example.org" not in repr(state)


def test_poh_email_attestation_submit_rejects_replay() -> None:
    state = _base_state()
    att = _attestation()
    apply_poh_email_attestation_submit(state, _env(att))

    with pytest.raises(ApplyError) as exc:
        apply_poh_email_attestation_submit(state, _env(att))

    assert exc.value.reason == "attestation_replayed"


def test_poh_email_attestation_submit_rejects_subject_signer_mismatch() -> None:
    state = _base_state()

    with pytest.raises(ApplyError) as exc:
        apply_poh_email_attestation_submit(state, _env(_attestation(), signer="@mallory"))

    assert exc.value.reason == "subject_signer_mismatch"


def test_poh_email_attestation_submit_rejects_suspended_oracle() -> None:
    state = _base_state()
    state["oracle_registry"]["oracles"]["oracle:poh-email:1"]["status"] = "suspended"

    with pytest.raises(ApplyError) as exc:
        apply_poh_email_attestation_submit(state, _env(_attestation()))

    assert exc.value.reason == "oracle_not_active"
