from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.node_operator_responsibilities import (
    evaluate_storage_responsibility,
    evaluate_validator_responsibility,
)
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt

VALID_CID = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"


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
                "reputation_milli": 10_000,
                "devices": {"by_id": {"node-1": {"device_id": "node-1", "device_type": "node", "pubkey": "node-pub-1", "revoked": False}}},
            }
        },
        "roles": {"node_operators": {"active_set": ["@op"], "by_id": {"@op": {"account_id": "@op", "enrolled": True, "active": True, "responsibilities": {}}}}},
        "params": {"ipfs_replication_factor": 1, "storage_proof_ttl_blocks": 50},
    }


def _storage_opt_in(st: dict) -> None:
    apply_tx(st, _env("NODE_OPERATOR_STORAGE_OPT_IN", "@op", 1, {"account_id": "@op", "node_pubkey": "node-pub-1", "declared_capacity_bytes": 1_000_000}))


def test_storage_capacity_probe_must_cover_protocol_offsets_before_verification() -> None:
    st = _state()
    _storage_opt_in(st)

    issued = apply_tx(st, _env("STORAGE_CHALLENGE_ISSUE", "SYSTEM", 2, {"proof_scope": "capacity_probe", "challenge_id": "probe-1", "account_id": "@op", "node_pubkey": "node-pub-1", "reserved_capacity_bytes": 900_000, "sample_count": 3, "sample_size_bytes": 1024, "challenge_seed": "seed", "expires_height": 20}, system=True))
    offsets = issued["probe_offsets"]
    assert len(offsets) == 3
    assert evaluate_storage_responsibility(st, "@op").status == "probe_open"

    with pytest.raises(ApplyError):
        apply_tx(st, _env("STORAGE_CHALLENGE_RESPOND", "@op", 3, {"challenge_id": "probe-1", "response_commitment": "sha256:root", "probe_responses": [{"offset": offsets[0], "size": 1024, "response_hash": "sha256:one"}]}))

    apply_tx(st, _env("STORAGE_CHALLENGE_RESPOND", "@op", 4, {"challenge_id": "probe-1", "response_commitment": "sha256:root", "probe_responses": [{"offset": o, "size": 1024, "response_hash": f"sha256:{i}"} for i, o in enumerate(offsets)]}))
    assert evaluate_storage_responsibility(st, "@op").status == "verification_pending"

    verified = apply_tx(st, _env("STORAGE_CAPACITY_PROOF_VERIFY", "SYSTEM", 5, {"challenge_id": "probe-1", "verification_status": "verified", "verified_capacity_bytes": 800_000, "verification_receipt_hash": "sha256:receipt", "verifier_id": "SYSTEM"}, system=True))
    assert verified["verified"] is True
    storage = evaluate_storage_responsibility(st, "@op")
    assert storage.active is True
    assert storage.details["proven_capacity_bytes"] == 800_000
    assert storage.details["proof_expires_height"] == 60


def test_legacy_storage_offer_without_responsibility_is_removed() -> None:
    st = {"height": 1, "accounts": {"@legacy": {"poh_tier": 2}}, "storage": {"operators": {"@legacy": {"enabled": True, "capacity_bytes": 1_000_000}}}}
    with pytest.raises(ApplyError):
        apply_tx(st, _env("STORAGE_OFFER_CREATE", "@legacy", 1, {"offer_id": "legacy", "capacity_bytes": 1_000}))
    pin = apply_tx(st, _env("IPFS_PIN_REQUEST", "@user", 2, {"pin_id": "pin", "cid": VALID_CID, "size_bytes": 128}))
    assert pin["targets"] == []


def test_storage_proof_expiry_and_allocation_accounting_block_overallocation() -> None:
    st = _state()
    _storage_opt_in(st)
    issued = apply_tx(st, _env("STORAGE_CHALLENGE_ISSUE", "SYSTEM", 2, {"proof_scope": "capacity_probe", "challenge_id": "probe-2", "account_id": "@op", "reserved_capacity_bytes": 100_000, "sample_count": 1, "sample_size_bytes": 512, "expires_height": 20}, system=True))
    offset = issued["probe_offsets"][0]
    apply_tx(st, _env("STORAGE_CHALLENGE_RESPOND", "@op", 3, {"challenge_id": "probe-2", "response_commitment": "sha256:r", "probe_responses": [{"offset": offset, "size": 512, "response_hash": "sha256:r0"}]}))
    apply_tx(st, _env("STORAGE_CAPACITY_PROOF_VERIFY", "SYSTEM", 4, {"challenge_id": "probe-2", "verification_status": "verified", "verified_capacity_bytes": 100_000, "verification_receipt_hash": "sha256:receipt", "proof_ttl_blocks": 5}, system=True))

    apply_tx(st, _env("STORAGE_OFFER_CREATE", "@op", 5, {"offer_id": "offer", "capacity_bytes": 100_000}))
    apply_tx(st, _env("STORAGE_LEASE_CREATE", "@user", 6, {"offer_id": "offer", "lease_id": "lease", "size_bytes": 60_000, "duration_blocks": 10}))
    assert evaluate_storage_responsibility(st, "@op").details["allocated_capacity_bytes"] == 60_000
    with pytest.raises(ApplyError):
        apply_tx(st, _env("STORAGE_LEASE_CREATE", "@user", 7, {"offer_id": "offer", "lease_id": "too-much", "size_bytes": 50_000, "duration_blocks": 10}))
    st["height"] = 16
    assert evaluate_storage_responsibility(st, "@op").active is False


def test_validator_readiness_verification_required_before_active_validator_responsibility() -> None:
    st = _state()
    apply_tx(st, _env("NODE_OPERATOR_VALIDATOR_OPT_IN", "@op", 1, {"account_id": "@op", "node_pubkey": "node-pub-1"}))
    pending = evaluate_validator_responsibility(st, "@op")
    assert pending.active is False
    assert "validator_readiness_pending" in pending.reasons

    with pytest.raises(ApplyError):
        apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", "SYSTEM", 2, {"account_id": "@op", "verification_status": "verified", "tx_index_hash": "tx", "readiness_receipt_hash": "rx", "readiness_expires_height": 20}, system=True))

    receipt = build_validator_readiness_receipt(
        account_id="@op",
        node_pubkey="node-pub-1",
        bft_pubkey="bft-pub",
        chain_id="weall-prod",
        schema_version="1",
        protocol_version="1.25.0",
        manifest_hash="manifest",
        tx_index_hash="tx",
        runtime_profile_hash="runtime",
        readiness_expires_height=20,
    )
    payload = dict(receipt)
    payload["verification_status"] = "verified"
    apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", "SYSTEM", 3, payload, system=True))
    ready = evaluate_validator_responsibility(st, "@op")
    assert ready.active is True
    st["height"] = 21
    expired = evaluate_validator_responsibility(st, "@op")
    assert expired.active is False
    assert "validator_readiness_expired" in expired.reasons
