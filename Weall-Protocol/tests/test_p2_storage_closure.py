from __future__ import annotations

import pytest

from weall.runtime import scheduler_pipeline
from weall.runtime.apply.storage import StorageApplyError, apply_storage
from weall.runtime.runtime_context import SchedulerSet
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.tx_schema import validate_tx_envelope

CID_1 = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7xqz7i"
CID_2 = "bafkreibm6jgqve7pzq3p7uwz3r3owz3oob7xjlkvyq5m4jdokwfvlq45aq"


def _system(tx_type: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM",
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent="storage:p2",
        system=True,
    )


def _strict(tx_type: str, payload: dict) -> None:
    validate_tx_envelope(
        {
            "tx_type": tx_type,
            "signer": "@alice",
            "nonce": 1,
            "payload": payload,
            "sig": "sig",
            "parent": None,
            "system": False,
            "chain_id": "test",
        }
    )


def test_p2_stor004_lease_size_bytes_passes_strict_canonical_admission() -> None:
    _strict(
        "STORAGE_LEASE_CREATE",
        {
            "offer_id": "offer:p2",
            "lease_id": "lease:p2",
            "duration_blocks": 10,
            "size_bytes": 4096,
        },
    )


def test_p2_stor002_confirm_durability_fields_pass_strict_canonical_admission() -> None:
    validate_tx_envelope(
        {
            "tx_type": "IPFS_PIN_CONFIRM",
            "signer": "SYSTEM",
            "nonce": 2,
            "payload": {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-a",
                "ok": True,
                "retrieval_ok": True,
                "availability_ok": True,
                "retrieval_probe_id": "probe:p2",
                "retrieval_sha256": "sha256:p2",
                "proof_hash": "proof:p2",
            },
            "sig": "sig",
            "parent": "storage:p2",
            "system": True,
            "chain_id": "test",
        }
    )


def test_p2_stor002_pin_confirm_binds_existing_cid_and_distinct_current_targets() -> None:
    state = {
        "height": 10,
        "params": {"ipfs_replication_factor": 2},
        "storage": {
            "pins": {
                "pin:p2": {
                    "pin_id": "pin:p2",
                    "cid": CID_1,
                    "size_bytes": 0,
                    "targets": ["op-a", "op-b"],
                    "replication_factor": 2,
                    "status": "requested",
                }
            }
        },
    }

    with pytest.raises(StorageApplyError, match="pin_not_found"):
        apply_storage(
            state, _system("IPFS_PIN_CONFIRM", 1, {"pin_id": "missing", "operator_id": "op-a"})
        )

    with pytest.raises(StorageApplyError, match="pin_cid_mismatch"):
        apply_storage(
            state,
            _system(
                "IPFS_PIN_CONFIRM",
                2,
                {"pin_id": "pin:p2", "cid": CID_2, "operator_id": "op-a", "ok": True},
            ),
        )

    with pytest.raises(StorageApplyError, match="pin_confirm_operator_not_current_target"):
        apply_storage(
            state,
            _system(
                "IPFS_PIN_CONFIRM",
                3,
                {"pin_id": "pin:p2", "cid": CID_1, "operator_id": "op-c", "ok": True},
            ),
        )

    apply_storage(
        state,
        _system(
            "IPFS_PIN_CONFIRM",
            4,
            {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-a",
                "ok": True,
                "retrieval_ok": True,
            },
        ),
    )
    rec = state["storage"]["pins"]["pin:p2"]
    assert rec["confirmed_targets"] == ["op-a"]
    assert rec["retrieval_confirmed_targets"] == ["op-a"]
    assert rec["status"] != "confirmed"
    assert rec["durability_status"] != "retrieval_confirmed"

    # Repeating one target cannot satisfy RF=2.
    apply_storage(
        state,
        _system(
            "IPFS_PIN_CONFIRM",
            5,
            {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-a",
                "ok": True,
                "retrieval_ok": True,
            },
        ),
    )
    assert rec["confirmed_target_count"] == 1
    assert rec["retrieval_confirmed_target_count"] == 1

    apply_storage(
        state,
        _system(
            "IPFS_PIN_CONFIRM",
            6,
            {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-b",
                "ok": True,
                "retrieval_ok": True,
            },
        ),
    )
    assert rec["confirmed_targets"] == ["op-a", "op-b"]
    assert rec["retrieval_confirmed_targets"] == ["op-a", "op-b"]
    assert rec["status"] == "confirmed"
    assert rec["durability_status"] == "retrieval_confirmed"
    assert rec["availability_status"] == "available"


def _noop(*_args: object, **_kwargs: object) -> None:
    return None


def _noop_schedulers() -> SchedulerSet:
    return SchedulerSet(
        schedule_account_recovery_system_txs=_noop,
        schedule_poh_async_system_txs=_noop,
        schedule_poh_tier2_system_txs=_noop,
        schedule_poh_live_system_txs=_noop,
        schedule_node_operator_system_txs=_noop,
        schedule_reputation_accrual_system_txs=_noop,
        tick_governance_lifecycle=_noop,
        tick_dispute_lifecycle=_noop,
        system_tx_emitter=lambda *_args, **_kwargs: [],
        prune_emitted_system_queue=_noop,
    )


def test_p2_stor003_core_scheduler_expires_lease_and_releases_only_reserved_capacity_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "height": 9,
        "storage": {
            "leases": {
                "lease:p2": {
                    "lease_id": "lease:p2",
                    "operator_id": "op-a",
                    "operator": "op-a",
                    "lessee": "@alice",
                    "status": "active",
                    "start_height": 5,
                    "end_height": 10,
                    "size_bytes": 600,
                    "capacity_released": False,
                }
            },
            "operators": {
                "op-a": {
                    "allocated_bytes": 600,
                    "allocated_capacity_bytes": 600,
                    "used_bytes": 777,
                }
            },
        },
        "roles": {
            "node_operators": {
                "by_id": {
                    "op-a": {
                        "responsibilities": {
                            "storage": {
                                "allocated_capacity_bytes": 600,
                                "used_capacity_bytes": 777,
                            }
                        }
                    }
                }
            }
        },
    }
    for name in (
        "process_tier2_lifecycle",
        "process_evidence_lifecycle",
        "repair_pending_content_escalations",
        "repair_unassigned_dispute_panels",
    ):
        monkeypatch.setattr(scheduler_pipeline, name, _noop)

    schedulers = _noop_schedulers()
    scheduler_pipeline.run_core_schedulers(state, next_height=9, scheduler_set=schedulers)
    assert state["storage"]["leases"]["lease:p2"]["status"] == "active"

    scheduler_pipeline.run_core_schedulers(state, next_height=10, scheduler_set=schedulers)
    lease = state["storage"]["leases"]["lease:p2"]
    storage = state["roles"]["node_operators"]["by_id"]["op-a"]["responsibilities"]["storage"]
    operator = state["storage"]["operators"]["op-a"]
    assert lease["status"] == "expired"
    assert lease["expired_at_height"] == 10
    assert lease["capacity_released"] is True
    assert storage["allocated_capacity_bytes"] == 0
    assert operator["allocated_bytes"] == 0
    assert storage["used_capacity_bytes"] == 777
    assert operator["used_bytes"] == 777

    scheduler_pipeline.run_core_schedulers(state, next_height=11, scheduler_set=schedulers)
    assert storage["allocated_capacity_bytes"] == 0
    assert storage["used_capacity_bytes"] == 777


def test_p2_stor003_expired_lease_rejects_renewal_and_storage_proof() -> None:
    state = {
        "height": 10,
        "storage": {
            "leases": {
                "lease:p2": {
                    "lease_id": "lease:p2",
                    "operator_id": "op-a",
                    "operator": "op-a",
                    "lessee": "@alice",
                    "status": "expired",
                    "end_height": 10,
                }
            },
            "proofs": {},
        },
    }
    with pytest.raises(StorageApplyError, match="lease_not_active"):
        apply_storage(
            state,
            TxEnvelope(
                tx_type="STORAGE_LEASE_RENEW",
                signer="@alice",
                nonce=1,
                payload={"lease_id": "lease:p2", "add_blocks": 5},
            ),
        )
    with pytest.raises(StorageApplyError, match="lease_not_active"):
        apply_storage(
            state,
            TxEnvelope(
                tx_type="STORAGE_PROOF_SUBMIT",
                signer="op-a",
                nonce=2,
                payload={"lease_id": "lease:p2"},
            ),
        )
