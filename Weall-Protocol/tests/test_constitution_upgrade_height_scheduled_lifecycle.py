from __future__ import annotations

import copy
import json

import pytest

from weall.runtime.apply.protocol import ProtocolApplyError, apply_protocol, constitution_effective_view
from weall.runtime.tx_admission_types import TxEnvelope


DOC_HASH = "sha256:" + "a" * 64
TRACE_HASH = "sha256:" + "b" * 64
RIGHTS_HASH = "sha256:" + "c" * 64


def _env(tx_type: str, nonce: int, payload: dict, *, signer: str = "@system", parent: str | None = None) -> TxEnvelope:
    if parent is None:
        parent = "CONSTITUTION_UPGRADE_DECLARE" if tx_type == "CONSTITUTION_UPGRADE_ACTIVATE" else "GOV_EXECUTE"
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=True, parent=parent)


def _state_hash(state: dict) -> str:
    return json.dumps(state, sort_keys=True, separators=(",", ":"))


def _declare_payload(**extra: object) -> dict:
    payload = {
        "constitution_id": "const-v0-2",
        "constitution_version": "v0.2",
        "document_hash": DOC_HASH,
        "traceability_hash": TRACE_HASH,
        "rights_floor_hash": RIGHTS_HASH,
    }
    payload.update(extra)
    return payload


def test_constitution_upgrade_declare_records_public_hash_metadata_only() -> None:
    state = {"height": 100}

    out = apply_protocol(state, _env("CONSTITUTION_UPGRADE_DECLARE", 1, _declare_payload()))

    assert out is not None
    rec = state["constitution"]["upgrades"]["const-v0-2"]
    assert rec["status"] == "declared"
    assert rec["version"] == "v0.2"
    assert rec["document_hash"] == DOC_HASH
    assert rec["traceability_hash"] == TRACE_HASH
    assert rec["declared_at_height"] == 101
    assert rec["record_only_boundary"]["document_fetched"] is False
    assert rec["record_only_boundary"]["private_identity_evidence_allowed"] is False
    assert rec["record_only_boundary"]["rights_floor_bypass_allowed"] is False


def test_constitution_upgrade_rejects_invalid_hash_private_evidence_and_rights_floor_bypass() -> None:
    with pytest.raises(ProtocolApplyError) as bad_hash:
        apply_protocol(
            {"height": 1},
            _env("CONSTITUTION_UPGRADE_DECLARE", 1, _declare_payload(constitution_id="bad", document_hash="not-a-sha")),
        )
    assert bad_hash.value.reason == "constitution_hash_must_be_sha256"

    with pytest.raises(ProtocolApplyError) as private_evidence:
        apply_protocol(
            {"height": 1},
            _env("CONSTITUTION_UPGRADE_DECLARE", 2, _declare_payload(constitution_id="private", government_id="raw-id")),
        )
    assert private_evidence.value.reason == "constitution_upgrade_contains_private_identity_evidence"
    assert private_evidence.value.details["fields"] == ["government_id"]

    with pytest.raises(ProtocolApplyError) as bypass:
        apply_protocol(
            {"height": 1},
            _env("CONSTITUTION_UPGRADE_DECLARE", 3, _declare_payload(constitution_id="bypass", bypass_rights_floor=True)),
        )
    assert bypass.value.reason == "constitution_upgrade_rights_floor_bypass_forbidden"


def test_constitution_upgrade_duplicate_declare_is_idempotent_only_for_identical_record() -> None:
    state = {"height": 5}
    first = apply_protocol(state, _env("CONSTITUTION_UPGRADE_DECLARE", 1, _declare_payload()))
    second = apply_protocol(state, _env("CONSTITUTION_UPGRADE_DECLARE", 2, _declare_payload()))

    assert first is not None and second is not None
    assert second["deduped"] is True
    assert state["constitution"]["upgrades"]["const-v0-2"]["declared_at_nonce"] == 1

    with pytest.raises(ProtocolApplyError) as conflict:
        apply_protocol(
            state,
            _env("CONSTITUTION_UPGRADE_DECLARE", 3, _declare_payload(constitution_version="v0.3")),
        )
    assert conflict.value.reason == "constitution_upgrade_already_declared"


def test_constitution_activation_is_future_height_scheduled_and_record_only() -> None:
    state = {"height": 20}
    apply_protocol(state, _env("CONSTITUTION_UPGRADE_DECLARE", 1, _declare_payload()))

    with pytest.raises(ProtocolApplyError) as not_future:
        apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 2, {"constitution_id": "const-v0-2", "activation_height": 21}))
    assert not_future.value.reason == "upgrade_activation_height_must_be_future"

    out = apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 3, {"constitution_id": "const-v0-2", "activation_height": 60}))
    assert out is not None
    rec = out["governance_activation_record"]
    assert rec["status"] == "scheduled"
    assert rec["activation_height"] == 60
    assert rec["activation_pending"] is True
    assert rec["effective_now"] is False
    assert rec["record_only_boundary"]["automatic_constitution_apply_supported"] is False
    assert state["constitution"]["scheduled_upgrades"]["const-v0-2"]["activation_height"] == 60


def test_constitution_activation_rejects_mismatched_version_or_hash_and_duplicate_conflict() -> None:
    state = {"height": 30}
    apply_protocol(state, _env("CONSTITUTION_UPGRADE_DECLARE", 1, _declare_payload()))

    with pytest.raises(ProtocolApplyError) as version_mismatch:
        apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 2, {"constitution_id": "const-v0-2", "version": "v0.3", "activation_height": 80}))
    assert version_mismatch.value.reason == "constitution_activation_version_mismatch"

    with pytest.raises(ProtocolApplyError) as hash_mismatch:
        apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 3, {"constitution_id": "const-v0-2", "document_hash": "sha256:" + "d" * 64, "activation_height": 80}))
    assert hash_mismatch.value.reason == "constitution_activation_document_hash_mismatch"

    first = apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 4, {"constitution_id": "const-v0-2", "activation_height": 80}))
    second = apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 5, {"constitution_id": "const-v0-2", "activation_height": 80}))
    assert first is not None and second is not None
    assert second["deduped"] is True

    with pytest.raises(ProtocolApplyError) as duplicate_conflict:
        apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 6, {"constitution_id": "const-v0-2", "activation_height": 81}))
    assert duplicate_conflict.value.reason == "constitution_duplicate_activation_conflict"


def test_constitution_effective_view_uses_block_height_without_mutating_state() -> None:
    state = {"height": 40, "constitution": {"active": {"version": "v0.1", "document_hash": "sha256:" + "0" * 64}}}
    apply_protocol(state, _env("CONSTITUTION_UPGRADE_DECLARE", 1, _declare_payload()))
    apply_protocol(state, _env("CONSTITUTION_UPGRADE_ACTIVATE", 2, {"constitution_id": "const-v0-2", "activation_height": 75}))
    before_hash = _state_hash(state)

    before = constitution_effective_view(state, at_height=74)
    at = constitution_effective_view(state, at_height=75)
    after = constitution_effective_view(state, at_height=100)

    assert _state_hash(state) == before_hash
    assert before["active"]["version"] == "v0.1"
    assert before["pending_scheduled_count"] == 1
    assert at["active"]["version"] == "v0.2"
    assert after["active"]["document_hash"] == DOC_HASH
    assert at["activation_model"] == "read_model_by_block_height_record_only"


def test_constitution_upgrade_lifecycle_replays_to_identical_state_roots() -> None:
    txs = [
        _env("CONSTITUTION_UPGRADE_DECLARE", 1, _declare_payload()),
        _env("CONSTITUTION_UPGRADE_ACTIVATE", 2, {"constitution_id": "const-v0-2", "activation_delay_blocks": 12, "_due_height": 90}),
    ]

    leader = {"height": 50}
    follower = copy.deepcopy(leader)
    observer = copy.deepcopy(leader)
    for state in (leader, follower, observer):
        for tx in txs:
            apply_protocol(state, tx)

    assert _state_hash(leader) == _state_hash(follower) == _state_hash(observer)
    record = leader["constitution"]["scheduled_upgrades"]["const-v0-2"]
    assert record["governance_approved_at_height"] == 90
    assert record["activation_height"] == 102
    assert record["record_only_boundary"]["document_fetched"] is False
