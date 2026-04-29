from __future__ import annotations

import hashlib

import pytest

from weall.runtime.poh.email_attestation import (
    ATTESTATION_TYPE,
    build_unsigned_email_control_attestation_v1,
    domain_hash_for_attestation,
    email_hash_for_attestation,
    sign_email_control_attestation_v1,
    validate_attestation_for_state,
)
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_hex(label: str) -> str:
    return hashlib.sha256(("weall-test-ed25519:" + label).encode("utf-8")).hexdigest()


def _state_with_oracle(pubkey: str) -> dict:
    return {
        "chain_id": "weall-test",
        "height": 10,
        "oracle_registry": {
            "oracles": {
                "oracle:poh-email:1": {
                    "oracle_id": "oracle:poh-email:1",
                    "operator_account": "@oracle",
                    "oracle_type": "poh_email_tier1",
                    "oracle_pubkey": pubkey,
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
    }


def _signed_attestation(*, label: str = "@oracle", account_id: str = "@alice") -> tuple[dict, str]:
    pubkey, _ = deterministic_ed25519_keypair(label=label)
    email_hash = email_hash_for_attestation(
        normalized_email="alice@example.org",
        salt="test-salt",
        account_id=account_id,
    )
    domain_hash = domain_hash_for_attestation(
        normalized_email="alice@example.org",
        salt="test-salt",
        account_id=account_id,
    )
    unsigned = build_unsigned_email_control_attestation_v1(
        chain_id="weall-test",
        account_id=account_id,
        email_hash=email_hash,
        domain_hash=domain_hash,
        challenge_id="challenge:1",
        issued_at_height=5,
        expires_at_height=20,
        oracle_id="oracle:poh-email:1",
    )
    return sign_email_control_attestation_v1(unsigned, oracle_private_key=_seed_hex(label)), pubkey


def test_email_control_attestation_signature_round_trip() -> None:
    attestation, pubkey = _signed_attestation()
    state = _state_with_oracle(pubkey)

    ok, reason, payload, oracle = validate_attestation_for_state(
        state,
        attestation,
        account_id="@alice",
        current_height=10,
    )

    assert ok is True
    assert reason == "ok"
    assert payload is not None
    assert payload["type"] == ATTESTATION_TYPE
    assert oracle is not None
    assert oracle["oracle_id"] == "oracle:poh-email:1"


def test_email_control_attestation_rejects_raw_email_field() -> None:
    attestation, pubkey = _signed_attestation()
    state = _state_with_oracle(pubkey)
    attestation["email"] = "alice@example.org"

    ok, reason, payload, oracle = validate_attestation_for_state(
        state,
        attestation,
        account_id="@alice",
        current_height=10,
    )

    assert ok is False
    assert reason == "raw_identity_field_forbidden"
    assert payload is None
    assert oracle is None


def test_email_control_attestation_rejects_expired_height() -> None:
    attestation, pubkey = _signed_attestation()
    state = _state_with_oracle(pubkey)

    ok, reason, _, _ = validate_attestation_for_state(
        state,
        attestation,
        account_id="@alice",
        current_height=21,
    )

    assert ok is False
    assert reason == "attestation_expired"


def test_email_control_attestation_rejects_suspended_oracle() -> None:
    attestation, pubkey = _signed_attestation()
    state = _state_with_oracle(pubkey)
    state["oracle_registry"]["oracles"]["oracle:poh-email:1"]["status"] = "suspended"

    ok, reason, _, _ = validate_attestation_for_state(
        state,
        attestation,
        account_id="@alice",
        current_height=10,
    )

    assert ok is False
    assert reason == "oracle_not_active"


def test_email_control_attestation_rejects_wrong_account() -> None:
    attestation, pubkey = _signed_attestation(account_id="@alice")
    state = _state_with_oracle(pubkey)

    ok, reason, _, _ = validate_attestation_for_state(
        state,
        attestation,
        account_id="@bob",
        current_height=10,
    )

    assert ok is False
    assert reason == "attestation_account_mismatch"


def test_email_control_attestation_proof_commitment_is_bound_to_payload() -> None:
    attestation, pubkey = _signed_attestation()
    state = _state_with_oracle(pubkey)
    attestation["challenge_id"] = "challenge:tampered"

    ok, reason, _, _ = validate_attestation_for_state(
        state,
        attestation,
        account_id="@alice",
        current_height=10,
    )

    assert ok is False
    assert reason == "proof_commitment_mismatch"
