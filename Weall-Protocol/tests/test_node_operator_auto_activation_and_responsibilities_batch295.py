from __future__ import annotations

import json

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs


def _env(tx_type: str, payload: dict, *, signer: str = "SYSTEM", system: bool = True) -> dict:
    return {"tx_type": tx_type, "signer": signer, "nonce": 0, "payload": payload, "sig": "", "system": system}


def _state(*, tier: int = 2, rep: int = 0, active: bool = False, node_pub: str = "node-pub") -> dict:
    return {
        "accounts": {
            "@op": {
                "nonce": 0,
                "poh_tier": int(tier),
                "reputation_milli": int(rep),
                "banned": False,
                "locked": False,
                "devices": {
                    "by_id": {
                        "node:primary": {
                            "device_type": "node",
                            "pubkey": node_pub,
                            "revoked": False,
                        }
                    }
                },
            }
        },
        "roles": {
            "node_operators": {
                "by_id": {"@op": {"account_id": "@op", "enrolled": True, "active": active}},
                "active_set": ["@op"] if active else [],
            }
        },
    }


def test_eligible_node_operator_enrollment_auto_queues_and_applies_activation_batch295() -> None:
    st = _state(tier=2, rep=0, active=False)

    enqueued = schedule_node_operator_system_txs(st, next_height=7)
    assert enqueued == 1
    queue = st.get("system_queue")
    assert isinstance(queue, list)
    assert queue[0]["tx_type"] == "ROLE_NODE_OPERATOR_ACTIVATE"
    assert queue[0]["payload"] == {"account_id": "@op"}
    assert queue[0]["phase"] == "post"

    apply_tx(st, _env("ROLE_NODE_OPERATOR_ACTIVATE", {"account_id": "@op"}))
    rec = st["roles"]["node_operators"]["by_id"]["@op"]
    assert rec["active"] is True
    assert "@op" in st["roles"]["node_operators"]["active_set"]
    assert rec["responsibilities"]["validator"]["opted_in"] is False
    assert rec["responsibilities"]["validator"]["active"] is False
    assert rec["responsibilities"]["validator"]["readiness_status"] == "not_requested"
    assert rec["responsibilities"]["storage"]["proven_capacity_bytes"] == 0


def test_node_operator_auto_activation_blocks_ineligible_enrollment_batch295() -> None:
    tier1 = _state(tier=1, rep=9999, active=False)
    assert schedule_node_operator_system_txs(tier1, next_height=7) == 0
    rec = tier1["roles"]["node_operators"]["by_id"]["@op"]
    assert rec["activation_check"] == "poh_tier_insufficient"

    missing_node_key = _state(tier=2, rep=9999, active=False)
    missing_node_key["accounts"]["@op"]["devices"] = {"by_id": {}}
    assert schedule_node_operator_system_txs(missing_node_key, next_height=7) == 0
    rec2 = missing_node_key["roles"]["node_operators"]["by_id"]["@op"]
    assert rec2["activation_check"] == "node_key_missing"


def test_user_cannot_directly_apply_node_operator_activation_batch295() -> None:
    st = _state(tier=2, rep=0, active=False)
    with pytest.raises(Exception) as exc:
        apply_tx(st, _env("ROLE_NODE_OPERATOR_ACTIVATE", {"account_id": "@op"}, signer="@op", system=False))
    assert "system_only" in str(exc.value)


def _preflight(state: dict, *, roles: tuple[str, ...], bft: bool = False):
    return evaluate_production_preflight(
        state=state,
        node_id="node-1",
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="txhash",
        runtime_profile_hash="profilehash",
        requested_roles=roles,
        helper_requested=False,
        bft_requested=bft,
        sigverify_required=True,
        trusted_anchor_required=True,
    )


def test_baseline_node_operator_does_not_imply_validator_or_storage_responsibilities_batch295(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)

    st = _state(tier=2, rep=0, active=True)
    baseline = _preflight(st, roles=("node_operator",))
    assert baseline.passed
    assert baseline.effective_roles == ("general_service", "node_operator")
    assert baseline.reputation_required_milli == 0

    validator = _preflight(st, roles=("validator",), bft=True)
    assert not validator.passed
    assert "REPUTATION_INSUFFICIENT" in validator.maintenance_reasons
    assert "validator" not in validator.effective_roles

    storage_state = json.loads(json.dumps(st))
    storage_rec = storage_state["roles"]["node_operators"]["by_id"]["@op"]
    storage_rec["responsibilities"] = {
        "storage": {"opted_in": True, "active": True, "declared_capacity_bytes": 10_000, "proven_capacity_bytes": 0}
    }
    storage_state["accounts"]["@op"]["reputation_milli"] = 1500
    storage = _preflight(storage_state, roles=("storage_operator",))
    assert not storage.passed
    assert "ROLE_NOT_ACTIVE" in storage.maintenance_reasons

    proven_storage_state = json.loads(json.dumps(storage_state))
    proven_storage_state["accounts"]["@op"]["reputation_milli"] = 1500
    proven_storage = proven_storage_state["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]
    proven_storage["proven_capacity_bytes"] = 10_000
    proven_storage["reserved_capacity_bytes"] = 10_000
    proven_storage["probed_capacity_bytes"] = 10_000
    proven_storage["proof_status"] = "verified"
    proven_storage["proof_expires_height"] = 10_000
    proven_storage["allocated_capacity_bytes"] = 0
    proven_storage["used_capacity_bytes"] = 0
    proven = _preflight(proven_storage_state, roles=("storage_operator",))
    assert proven.passed
    assert proven.effective_roles == ("general_service", "storage_operator")
