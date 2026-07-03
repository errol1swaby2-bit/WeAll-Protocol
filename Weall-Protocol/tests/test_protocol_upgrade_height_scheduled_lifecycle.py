from __future__ import annotations

import copy
import json

import pytest

from weall.runtime.apply.protocol import ProtocolApplyError, apply_protocol
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, nonce: int, payload: dict, *, signer: str = "@system", parent: str | None = None) -> TxEnvelope:
    if parent is None:
        parent = "PROTOCOL_UPGRADE_DECLARE" if tx_type == "PROTOCOL_UPGRADE_ACTIVATE" else "GOV_EXECUTE"
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=True, parent=parent)


def _state_hash(state: dict) -> str:
    return json.dumps(state, sort_keys=True, separators=(",", ":"))


def test_upgrade_activation_is_scheduled_at_future_height_and_record_only() -> None:
    state = {"height": 100, "protocol": {"supported_upgrade_targets": ["v1.5.2"]}}

    declare = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_DECLARE",
            1,
            {"upgrade_id": "upgrade-scheduled", "target_version": "v1.5.2", "hash": "sha256:release"},
        ),
    )
    assert declare is not None
    assert declare["target_support"]["target_supported_by_local_config"] is True

    out = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_ACTIVATE",
            2,
            {"upgrade_id": "upgrade-scheduled", "target_version": "v1.5.2", "activation_height": 140},
        ),
    )

    assert out is not None
    record = out["governance_activation_record"]
    assert record["status"] == "scheduled"
    assert record["activation_height"] == 140
    assert record["software_applied"] is False
    assert record["artifact_fetched"] is False
    assert record["migration_executed"] is False
    assert record["rollback_available"] is False
    assert record["economics_activation_allowed"] is False
    assert state["protocol"]["upgrades"]["upgrade-scheduled"]["activation_height"] == 140
    assert state["protocol"]["scheduled_upgrades"]["upgrade-scheduled"]["activation_height"] == 140


def test_upgrade_activation_rejects_past_or_current_activation_height() -> None:
    state = {"height": 20}
    apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "u", "version": "v1.5.2"}))

    with pytest.raises(ProtocolApplyError) as exc:
        apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 2, {"upgrade_id": "u", "activation_height": 21}))

    assert exc.value.code == "forbidden"
    assert exc.value.reason == "upgrade_activation_height_must_be_future"


def test_upgrade_declare_rejects_unknown_target_when_supported_targets_are_configured() -> None:
    state = {"height": 1, "protocol": {"supported_upgrade_targets": ["v1.5.2"]}}

    with pytest.raises(ProtocolApplyError) as exc:
        apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "bad", "version": "v9.9.9"}))

    assert exc.value.code == "forbidden"
    assert exc.value.reason == "unsupported_protocol_upgrade_target"
    assert exc.value.details["supported_upgrade_targets"] == ["v1.5.2"]


def test_upgrade_activation_rejects_target_mismatch_and_duplicate_is_idempotent() -> None:
    state = {"height": 30}
    apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "u", "version": "v1.5.2"}))

    with pytest.raises(ProtocolApplyError) as exc:
        apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 2, {"upgrade_id": "u", "version": "v1.5.3"}))
    assert exc.value.reason == "upgrade_activation_target_mismatch"

    first = apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 3, {"upgrade_id": "u", "version": "v1.5.2"}))
    second = apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 4, {"upgrade_id": "u", "version": "v1.5.2"}))
    assert first is not None
    assert second is not None
    assert second["deduped"] is True
    assert state["protocol"]["upgrades"]["u"]["status"] == "scheduled"


def test_upgrade_lifecycle_replays_to_identical_state_roots() -> None:
    txs = [
        _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "u", "version": "v1.5.2", "hash": "sha256:x"}),
        _env("PROTOCOL_UPGRADE_ACTIVATE", 2, {"upgrade_id": "u", "activation_delay_blocks": 8}),
    ]

    leader_state = {"height": 44}
    follower_state = copy.deepcopy(leader_state)
    observer_state = copy.deepcopy(leader_state)

    for state in (leader_state, follower_state, observer_state):
        for tx in txs:
            apply_protocol(state, tx)

    assert _state_hash(leader_state) == _state_hash(follower_state) == _state_hash(observer_state)
    assert leader_state["protocol"]["governance_activation_record"]["activation_height"] == 53
    assert leader_state["protocol"]["governance_activation_record"]["automatic_upgrade_supported"] is False


def test_upgrade_duplicate_declare_is_idempotent_only_for_identical_record() -> None:
    state = {"height": 12}
    first = apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "dup", "version": "v1.5.2", "hash": "sha256:a"}))
    second = apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 2, {"upgrade_id": "dup", "version": "v1.5.2", "hash": "sha256:a"}))

    assert first is not None and second is not None
    assert second["deduped"] is True
    assert state["protocol"]["upgrades"]["dup"]["declared_at_nonce"] == 1

    with pytest.raises(ProtocolApplyError) as exc:
        apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 3, {"upgrade_id": "dup", "version": "v1.5.3", "hash": "sha256:b"}))

    assert exc.value.code == "conflict"
    assert exc.value.reason == "upgrade_already_declared"


def test_upgrade_duplicate_activation_rejects_conflicting_boundary_and_returns_matching_record() -> None:
    state = {"height": 50}
    apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "u1", "version": "v1.5.2"}))
    apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 2, {"upgrade_id": "u2", "version": "v1.5.3"}))
    apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 3, {"upgrade_id": "u1", "version": "v1.5.2", "activation_height": 90}))
    apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 4, {"upgrade_id": "u2", "version": "v1.5.3", "activation_height": 100}))

    duplicate = apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 5, {"upgrade_id": "u1", "version": "v1.5.2", "activation_height": 90}))
    assert duplicate is not None
    assert duplicate["deduped"] is True
    assert duplicate["governance_activation_record"]["upgrade_id"] == "u1"
    assert duplicate["governance_activation_record"]["activation_height"] == 90

    with pytest.raises(ProtocolApplyError) as exc:
        apply_protocol(state, _env("PROTOCOL_UPGRADE_ACTIVATE", 6, {"upgrade_id": "u1", "version": "v1.5.2", "activation_height": 91}))

    assert exc.value.code == "conflict"
    assert exc.value.reason == "upgrade_duplicate_activation_conflict"


def test_upgrade_domain_apply_requires_governance_parent_reference() -> None:
    state = {"height": 3}

    with pytest.raises(ProtocolApplyError) as exc:
        apply_protocol(
            state,
            TxEnvelope(
                tx_type="PROTOCOL_UPGRADE_DECLARE",
                signer="@system",
                nonce=1,
                payload={"upgrade_id": "no-parent", "version": "v1.5.2"},
                sig="",
                system=True,
            ),
        )

    assert exc.value.code == "forbidden"
    assert exc.value.reason == "protocol_upgrade_requires_governance_parent"


def test_upgrade_activation_cannot_smuggle_economics_activation() -> None:
    state = {
        "height": 30,
        "economics": {"enabled": False, "stage": "genesis_locked"},
    }
    apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "econ", "version": "v1.5.2"}))

    out = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_ACTIVATE",
            2,
            {
                "upgrade_id": "econ",
                "version": "v1.5.2",
                "enable_live_economics": True,
                "activate_economics": True,
                "enable_transfers": True,
            },
        ),
    )

    assert out is not None
    boundary = out["record_only_boundary"]
    assert {"enable_live_economics", "activate_economics", "enable_transfers"}.issubset(set(boundary["requested_execution_fields_ignored"]))
    record = out["governance_activation_record"]
    assert record["economics_activation_allowed"] is False
    assert record["activation_pending"] is True
    assert record["effective_now"] is False
    assert state["economics"] == {"enabled": False, "stage": "genesis_locked"}
