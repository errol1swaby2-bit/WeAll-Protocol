from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.node_operator_responsibilities import evaluate_storage_responsibility
from weall.runtime.storage_revalidation_scheduler import (
    apply_storage_revalidation_status,
    build_storage_revalidation_plan,
)
from weall.runtime.tx_admission import TxEnvelope

CID_A = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"
CID_B = "bafkreibm6jgqve7pzq3p7uwz3r3owz3oob7xjlkvyq5m4jdokwfvlq45aq"


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


def _state(*, height: int = 10, proof_expires_height: int = 100, proven: int = 100_000) -> dict:
    return {
        "height": height,
        "params": {
            "ipfs_replication_factor": 1,
            "storage_revalidation_window_blocks": 10,
            "storage_revalidation_challenge_ttl_blocks": 5,
            "storage_revalidation_sample_count": 2,
            "storage_revalidation_sample_size_bytes": 512,
            "storage_max_failed_challenges": 3,
            "storage_max_missed_challenges": 3,
            "storage_min_availability_score_milli": 500,
        },
        "accounts": {
            "@op": {
                "poh_tier": 2,
                "reputation_milli": 5000,
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
                        "node_pubkey": "node-pub-1",
                        "responsibilities": {
                            "storage": {
                                "opted_in": True,
                                "active": True,
                                "proof_status": "verified",
                                "declared_capacity_bytes": int(proven),
                                "reserved_capacity_bytes": int(proven),
                                "probed_capacity_bytes": int(proven),
                                "proven_capacity_bytes": int(proven),
                                "allocated_capacity_bytes": 0,
                                "used_capacity_bytes": 0,
                                "proof_expires_height": int(proof_expires_height),
                                "last_successful_challenge_height": height,
                                "failed_challenge_count": 0,
                                "missed_challenge_count": 0,
                                "availability_score_milli": 1000,
                                "node_pubkey": "node-pub-1",
                            }
                        },
                    }
                },
            }
        },
        "storage": {
            "operators": {
                "@op": {
                    "account_id": "@op",
                    "enabled": True,
                    "capacity_bytes": int(proven),
                    "used_bytes": 0,
                    "allocated_bytes": 0,
                    "allocated_capacity_bytes": 0,
                }
            },
            "pins": {},
            "pin_confirms": [],
            "offers": {},
            "leases": {},
            "proofs": {},
            "challenges": {},
            "capacity_challenges": {},
            "reports": {},
            "payouts": [],
        },
    }


def _storage(st: dict) -> dict:
    return st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]


def _request_pin(st: dict, *, nonce: int, cid: str = CID_A, size: int = 10_000) -> dict:
    return apply_tx(st, _env("IPFS_PIN_REQUEST", "@user", nonce, {"pin_id": f"pin-{nonce}", "cid": cid, "size_bytes": size}))


def test_expired_storage_proof_blocks_new_allocation_but_preserves_existing_accounting_batch304() -> None:
    st = _state(height=10, proof_expires_height=20)
    pin = _request_pin(st, nonce=1, size=10_000)
    assert pin["targets"] == ["@op"]
    assert _storage(st)["allocated_capacity_bytes"] == 10_000

    st["height"] = 21
    expired = evaluate_storage_responsibility(st, "@op")
    assert expired.active is False
    assert "capacity_proof_expired" in expired.reasons

    pin2 = apply_tx(st, _env("IPFS_PIN_REQUEST", "@user", 2, {"pin_id": "after-expiry", "cid": CID_B, "size_bytes": 1_000}))
    assert pin2["targets"] == []
    assert _storage(st)["allocated_capacity_bytes"] == 10_000


def test_near_expiry_storage_proof_schedules_revalidation_without_blocking_allocation_batch304() -> None:
    st = _state(height=91, proof_expires_height=100)
    plan = build_storage_revalidation_plan(st)
    assert len(plan) == 1
    action = plan[0]
    assert action.status == "revalidation_due"
    assert action.reason == "proof_near_expiry"
    assert action.payload["sample_count"] == 2
    assert action.payload["expires_height"] == 96

    # Near-expiry proofs remain active until they actually expire.
    pin = _request_pin(st, nonce=1, size=1_000)
    assert pin["targets"] == ["@op"]


def test_successful_storage_revalidation_refreshes_expiry_and_failed_revalidation_pauses_batch304() -> None:
    st = _state(height=91, proof_expires_height=100)
    action = build_storage_revalidation_plan(st)[0]
    issue = apply_tx(st, _env("STORAGE_CHALLENGE_ISSUE", "SYSTEM", 1, action.payload, system=True))
    offset = issue["probe_offsets"][0]
    apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_RESPOND",
            "@op",
            2,
            {
                "challenge_id": action.challenge_id,
                "response_commitment": "sha256:response",
                "probe_responses": [{"offset": offset, "size": 512, "response_hash": "sha256:r0"}, {"offset": issue["probe_offsets"][1], "size": 512, "response_hash": "sha256:r1"}],
            },
        ),
    )
    apply_tx(
        st,
        _env(
            "STORAGE_CAPACITY_PROOF_VERIFY",
            "SYSTEM",
            3,
            {
                "challenge_id": action.challenge_id,
                "verification_status": "verified",
                "verified_capacity_bytes": 100_000,
                "verification_receipt_hash": "sha256:ok",
                "proof_ttl_blocks": 50,
            },
            system=True,
        ),
    )
    assert _storage(st)["proof_expires_height"] == 141
    assert evaluate_storage_responsibility(st, "@op").active is True

    st["height"] = 140
    action2 = build_storage_revalidation_plan(st)[0]
    apply_tx(st, _env("STORAGE_CHALLENGE_ISSUE", "SYSTEM", 4, action2.payload, system=True))
    apply_tx(
        st,
        _env(
            "STORAGE_CAPACITY_PROOF_VERIFY",
            "SYSTEM",
            5,
            {
                "challenge_id": action2.challenge_id,
                "verification_status": "failed",
                "verification_receipt_hash": "sha256:fail",
            },
            system=True,
        ),
    )
    failed = _storage(st)
    assert failed["active"] is False
    assert failed["proof_status"] == "failed"
    assert failed["failed_challenge_count"] == 1
    assert evaluate_storage_responsibility(st, "@op").active is False


def test_ipfs_pin_confirm_fail_and_release_are_idempotent_batch304() -> None:
    st = _state(height=10, proof_expires_height=100)
    pin = _request_pin(st, nonce=1, size=7_000)
    assert pin["targets"] == ["@op"]
    assert _storage(st)["allocated_capacity_bytes"] == 7_000

    apply_tx(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", 2, {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": "@op", "ok": True}, system=True))
    assert _storage(st)["used_capacity_bytes"] == 7_000
    assert st["storage"]["operators"]["@op"]["used_bytes"] == 7_000

    apply_tx(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", 3, {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": "@op", "release": True, "ok": False}, system=True))
    assert _storage(st)["allocated_capacity_bytes"] == 0
    assert _storage(st)["used_capacity_bytes"] == 0
    assert st["storage"]["operators"]["@op"]["allocated_bytes"] == 0
    assert st["storage"]["operators"]["@op"]["used_bytes"] == 0

    # Duplicate release is idempotent.
    apply_tx(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", 4, {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": "@op", "release": True, "ok": False}, system=True))
    assert _storage(st)["allocated_capacity_bytes"] == 0
    assert _storage(st)["used_capacity_bytes"] == 0


def test_failed_pin_confirmation_releases_reserved_allocation_once_batch304() -> None:
    st = _state(height=10, proof_expires_height=100)
    pin = _request_pin(st, nonce=1, size=8_000)
    assert _storage(st)["allocated_capacity_bytes"] == 8_000

    apply_tx(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", 2, {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": "@op", "ok": False}, system=True))
    assert _storage(st)["allocated_capacity_bytes"] == 0

    apply_tx(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", 3, {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": "@op", "ok": False}, system=True))
    assert _storage(st)["allocated_capacity_bytes"] == 0


def test_revalidation_status_materializer_expires_and_pauses_without_losing_accounting_batch304() -> None:
    st = _state(height=200, proof_expires_height=100)
    _storage(st)["allocated_capacity_bytes"] = 12_000
    _storage(st)["used_capacity_bytes"] = 4_000
    result = apply_storage_revalidation_status(st)
    assert result["updated"]
    storage = _storage(st)
    assert storage["active"] is False
    assert storage["proof_status"] == "expired"
    assert storage["allocated_capacity_bytes"] == 12_000
    assert storage["used_capacity_bytes"] == 4_000

    pin = _request_pin(st, nonce=1, size=1_000)
    assert pin["targets"] == []
