from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.node_operator_responsibilities import evaluate_storage_responsibility
from weall.runtime.tx_admission import TxEnvelope

VALID_CID_1 = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7xqz7i"
VALID_CID_2 = "bafkreibm6jgqve7pzq3p7uwz3r3owz3oob7xjlkvyq5m4jdokwfvlq45aq"


def _env(tx_type: str, signer: str, nonce: int, payload: dict | None = None, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload or {},
        sig="sig",
        parent=f"p:{max(0, nonce - 1)}" if system else None,
        system=system,
    )


def _state() -> dict:
    return {
        "height": 10,
        "accounts": {
            "@op": {
                "poh_tier": 2,
                "devices": {
                    "by_id": {
                        "node-1": {
                            "device_id": "node-1",
                            "device_type": "node",
                            "pubkey": "node-pub-1",
                            "revoked": False,
                        }
                    }
                },
            }
        },
        "roles": {
            "node_operators": {
                "active_set": ["@op"],
                "by_id": {
                    "@op": {
                        "account_id": "@op",
                        "enrolled": True,
                        "active": True,
                        "responsibilities": {
                            "storage": {
                                "opted_in": True,
                                "active": False,
                                "declared_capacity_bytes": 1_000_000,
                                "proven_capacity_bytes": 0,
                                "allocated_capacity_bytes": 0,
                                "proof_status": "pending",
                                "node_pubkey": "node-pub-1",
                            }
                        },
                    }
                },
            }
        },
        "params": {"ipfs_replication_factor": 1},
    }


def test_capacity_challenge_response_does_not_prove_capacity_until_system_verifies_batch301() -> None:
    st = _state()

    issue = apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_ISSUE",
            "SYSTEM",
            1,
            {
                "proof_scope": "capacity",
                "challenge_id": "cap-1",
                "account_id": "@op",
                "node_pubkey": "node-pub-1",
                "challenge_seed_commitment": "sha256:seed",
                "challenge_count": 2,
                "sample_size_bytes": 4096,
                "challenged_capacity_bytes": 800_000,
                "expires_height": 20,
            },
            system=True,
        ),
    )
    assert issue and issue["proof_scope"] == "capacity"
    assert st["storage"]["capacity_challenges"]["cap-1"]["status"] == "open"
    assert evaluate_storage_responsibility(st, "@op").status == "challenge_open"

    response = apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_RESPOND",
            "@op",
            2,
            {
                "challenge_id": "cap-1",
                "proof_scope": "capacity",
                "response_commitment": "sha256:response",
                "sample_response_commitments": ["sha256:s1", "sha256:s2"],
                "measured_capacity_bytes": 900_000,
            },
        ),
    )
    assert response and response["verification_pending"] is True
    storage = st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]
    assert storage["proven_capacity_bytes"] == 0
    assert storage["active"] is False
    assert evaluate_storage_responsibility(st, "@op").status == "verification_pending"


def test_only_system_verification_activates_storage_and_sets_proven_capacity_batch301() -> None:
    st = _state()
    apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_ISSUE",
            "SYSTEM",
            1,
            {
                "proof_scope": "capacity",
                "challenge_id": "cap-2",
                "account_id": "@op",
                "node_pubkey": "node-pub-1",
                "challenge_count": 1,
                "sample_size_bytes": 1024,
                "challenged_capacity_bytes": 1_000_000,
                "expires_height": 20,
            },
            system=True,
        ),
    )
    apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_RESPOND",
            "@op",
            2,
            {
                "challenge_id": "cap-2",
                "response_commitment": "sha256:response",
                "sample_response_commitments": ["sha256:s1"],
            },
        ),
    )

    with pytest.raises(ApplyError):
        apply_tx(
            st,
            _env(
                "STORAGE_CHALLENGE_RESPOND",
                "@op",
                3,
                {"challenge_id": "cap-2", "verification_status": "verified", "verified_capacity_bytes": 500_000},
            ),
        )

    verified = apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_RESPOND",
            "SYSTEM",
            4,
            {"challenge_id": "cap-2", "verification_status": "verified", "verified_capacity_bytes": 750_000},
            system=True,
        ),
    )
    assert verified and verified["verified"] is True
    storage = st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]
    assert storage["proven_capacity_bytes"] == 750_000
    assert storage["active"] is True
    assert storage["proof_status"] == "verified"
    assert st["storage"]["operators"]["@op"]["enabled"] is True
    assert st["storage"]["operators"]["@op"]["capacity_bytes"] == 750_000
    assert evaluate_storage_responsibility(st, "@op").active is True


def test_unproven_storage_operator_is_not_selected_for_ipfs_allocation_batch301() -> None:
    st = _state()

    # Legacy offer records alone are no longer enough to make an account eligible
    # for production storage allocation when node-operator responsibility state exists.
    with pytest.raises(ApplyError):
        apply_tx(st, _env("STORAGE_OFFER_CREATE", "@op", 1, {"offer_id": "offer-unproven", "capacity_bytes": 1000}))

    pin = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            "@user",
            2,
            {"pin_id": "pin-1", "cid": VALID_CID_1, "size_bytes": 128},
        ),
    )
    assert pin and pin["targets"] == []

    apply_tx(st, _env("STORAGE_CHALLENGE_ISSUE", "SYSTEM", 3, {"proof_scope": "capacity", "challenge_id": "cap-3", "account_id": "@op", "challenge_count": 1, "sample_size_bytes": 1024, "expires_height": 20}, system=True))
    apply_tx(st, _env("STORAGE_CHALLENGE_RESPOND", "@op", 4, {"challenge_id": "cap-3", "response_commitment": "sha256:r", "sample_response_commitments": ["sha256:s"]}))
    apply_tx(st, _env("STORAGE_CHALLENGE_RESPOND", "SYSTEM", 5, {"challenge_id": "cap-3", "verification_status": "verified", "verified_capacity_bytes": 500_000}, system=True))

    offer = apply_tx(st, _env("STORAGE_OFFER_CREATE", "@op", 6, {"offer_id": "offer-proven", "capacity_bytes": 1000}))
    assert offer and offer["applied"] == "STORAGE_OFFER_CREATE"
    pin2 = apply_tx(
        st,
        _env(
            "IPFS_PIN_REQUEST",
            "@user",
            7,
            {"pin_id": "pin-2", "cid": VALID_CID_2, "size_bytes": 128},
        ),
    )
    assert pin2 and pin2["targets"] == ["@op"]


def test_expired_capacity_challenge_cannot_be_used_batch301() -> None:
    st = _state()
    apply_tx(st, _env("STORAGE_CHALLENGE_ISSUE", "SYSTEM", 1, {"proof_scope": "capacity", "challenge_id": "cap-exp", "account_id": "@op", "challenge_count": 1, "sample_size_bytes": 1024, "expires_height": 11}, system=True))
    st["height"] = 12
    with pytest.raises(ApplyError):
        apply_tx(st, _env("STORAGE_CHALLENGE_RESPOND", "@op", 2, {"challenge_id": "cap-exp", "response_commitment": "sha256:r", "sample_response_commitments": ["sha256:s"]}))
    # Rejected expired responses are atomic and do not mutate state. A later
    # system maintenance transaction can mark the challenge expired, but the
    # stale operator response itself cannot advance proof state.
    storage = st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]
    assert storage["proof_status"] == "challenge_open"
    assert evaluate_storage_responsibility(st, "@op").status == "challenge_open"
