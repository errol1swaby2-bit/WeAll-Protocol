from __future__ import annotations

import pytest

from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict | None = None,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload or {},
            "sig": "sig",
            "system": bool(system),
            "parent": parent if parent is not None else (f"p:{tx_type}:{nonce}" if system else None),
        }
    )


def _econ_state() -> dict:
    genesis_time = 1_700_000_000
    unlock_time = genesis_time + 90 * 24 * 60 * 60
    return {
        "height": 1,
        "chain_id": "batch601-econ",
        "time": genesis_time,
        "params": {
            "genesis_time": genesis_time,
            "economic_unlock_time": unlock_time,
            "economics_enabled": False,
            "economics_activation_preconditions_required": True,
        },
        "economics": {"fee_policy": {"transfer_fee_int": 0}},
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 100},
            "@bob": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0},
            "SYSTEM": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "balance": 0},
        },
    }


def test_live_economics_stays_locked_without_governance_preconditions() -> None:
    state = _econ_state()

    with pytest.raises(ApplyError) as before_unlock:
        apply_tx(state, _env("BALANCE_TRANSFER", "@alice", 1, {"to": "@bob", "amount": 5}))
    assert before_unlock.value.reason in {"economics_time_locked", "economics are time-locked", "economics are disabled"}

    state["time"] = state["params"]["economic_unlock_time"]
    with pytest.raises(ApplyError) as before_activation:
        apply_tx(state, _env("BALANCE_TRANSFER", "@alice", 2, {"to": "@bob", "amount": 5}))
    assert before_activation.value.reason in {"economics_disabled", "economics are disabled"}

    with pytest.raises(ApplyError) as user_activation:
        apply_tx(state, _env("ECONOMICS_ACTIVATION", "@alice", 3, {"enable": True}))
    assert user_activation.value.reason in {"system_tx_required", "system_only"}

    with pytest.raises(ApplyError) as missing_preconditions:
        apply_tx(
            state,
            _env(
                "ECONOMICS_ACTIVATION",
                "SYSTEM",
                4,
                {"enable": True, "enforce_preconditions": True},
                system=True,
                parent="gov:econ-activation",
            ),
        )
    assert missing_preconditions.value.reason == "economics_activation_preconditions_not_satisfied"

    assert state["params"].get("economics_enabled") is False
    assert state["accounts"]["@alice"]["balance"] == 100
    assert state["accounts"]["@bob"]["balance"] == 0


def test_protocol_upgrade_activation_is_record_only_no_auto_apply() -> None:
    state = {"height": 20, "chain_id": "batch601-protocol"}
    declare = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_DECLARE",
            "SYSTEM",
            1,
            {
                "upgrade_id": "u-batch601",
                "version": "v1.5.601",
                "hash": "sha256:release",
                "auto_apply": True,
                "artifact_url": "https://example.invalid/release.tar.gz",
                "migration_steps": ["must-not-run"],
            },
            system=True,
            parent="gov:u-batch601",
        ),
    )
    assert declare is not None
    declare_boundary = declare["record_only_boundary"]
    assert declare_boundary["execution_model"] == "record_only_no_auto_apply"
    assert declare_boundary["artifact_apply_enabled"] is False
    assert declare_boundary["migration_execution_enabled"] is False
    assert set(declare_boundary["requested_execution_fields_ignored"]) == {
        "auto_apply",
        "artifact_url",
        "migration_steps",
    }

    activate = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_ACTIVATE",
            "SYSTEM",
            2,
            {
                "upgrade_id": "u-batch601",
                "version": "v1.5.601",
                "execute_migration": True,
                "restart_node": True,
                "rollback": True,
            },
            system=True,
            parent="gov:u-batch601",
        ),
    )
    assert activate is not None
    activation_record = activate["governance_activation_record"]
    assert activation_record["software_applied"] is False
    assert activation_record["artifact_fetched"] is False
    assert activation_record["migration_executed"] is False
    assert activation_record["rollback_available"] is False
    assert activation_record["operator_action_required"] is True
    assert activation_record["automatic_upgrade_supported"] is False
    activate_boundary = activate["record_only_boundary"]
    assert activate_boundary["rollback_execution_enabled"] is False
    assert activate_boundary["restart_or_process_control_enabled"] is False
    assert set(activate_boundary["requested_execution_fields_ignored"]) == {
        "execute_migration",
        "restart_node",
        "rollback",
    }
