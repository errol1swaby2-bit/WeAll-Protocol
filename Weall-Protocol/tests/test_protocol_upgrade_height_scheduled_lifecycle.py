from __future__ import annotations

import copy
import json

import pytest

from weall.runtime.apply.protocol import ProtocolApplyError, apply_protocol
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, nonce: int, payload: dict, *, signer: str = "@system") -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=True)


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
