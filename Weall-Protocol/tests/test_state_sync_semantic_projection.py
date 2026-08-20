from __future__ import annotations

import copy

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import (
    StateSyncService,
    StateSyncVerifyError,
    build_snapshot_anchor,
    sha256_hex_of,
    state_sync_snapshot_view,
)
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    SystemQueueCorruptionError,
    build_system_queue_lookup,
    enqueue_system_tx,
)


def _header(msg_type: MsgType) -> WireHeader:
    return WireHeader(
        type=msg_type,
        chain_id="sync-semantic",
        schema_version="1",
        tx_index_hash="tx-index",
        corr_id="semantic-projection",
    )


def _base_state() -> dict:
    return {
        "chain_id": "sync-semantic",
        "height": 10,
        "tip": "b10",
        "tip_hash": "h10",
        "created_ms": 100,
        "tip_ts_ms": 1_000,
        "accounts": {"@alice": {"nonce": 3}},
        "finalized": {"height": 9, "block_id": "b9"},
        "meta": {
            "protocol_version": "v-test",
            "schema_version": "1",
            "runtime_open": True,
            "clock_warning": "left-only",
        },
        "bft": {"last_voted_view": 7, "last_voted_block_id": "old"},
    }


def test_snapshot_identity_uses_canonical_transfer_projection() -> None:
    left = _base_state()
    right = copy.deepcopy(left)
    right["created_ms"] = 999
    right["tip_ts_ms"] = 9_999
    right["meta"]["runtime_open"] = False
    right["meta"]["clock_warning"] = "right-only"
    right["bft"] = {"last_voted_view": 99, "last_voted_block_id": "different"}

    assert compute_state_root(left) == compute_state_root(right)
    assert state_sync_snapshot_view(left) == state_sync_snapshot_view(right)
    assert build_snapshot_anchor(left) == build_snapshot_anchor(right)

    view = state_sync_snapshot_view(left)
    assert view["tip_hash"] == "h10"
    assert "created_ms" not in view
    assert "tip_ts_ms" not in view
    assert "bft" not in view
    assert view["meta"] == {"protocol_version": "v-test", "schema_version": "1"}


def test_snapshot_response_never_transfers_sender_local_runtime_metadata() -> None:
    state = _base_state()
    svc = StateSyncService(
        chain_id="sync-semantic",
        schema_version="1",
        tx_index_hash="tx-index",
        state_provider=lambda: state,
    )
    req = StateSyncRequestMsg(header=_header(MsgType.STATE_SYNC_REQUEST), mode="snapshot")

    resp = svc.handle_request(req)

    assert resp.ok is True
    assert resp.snapshot == state_sync_snapshot_view(state)
    assert isinstance(resp.snapshot, dict)
    assert "created_ms" not in resp.snapshot
    assert "tip_ts_ms" not in resp.snapshot
    assert "bft" not in resp.snapshot
    assert resp.snapshot["meta"] == {"protocol_version": "v-test", "schema_version": "1"}
    svc.verify_response(resp)


def test_state_sync_rejects_past_due_system_queue_at_import_boundary() -> None:
    state = _base_state()
    state.pop("bft", None)
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=5,
        phase="pre",
    )
    snapshot = state_sync_snapshot_view(state)
    snapshot_hash = sha256_hex_of(snapshot)
    finalized = state["finalized"]
    anchor = {
        "height": 10,
        "tip_hash": "h10",
        "state_root": compute_state_root(state),
        "finalized_height": finalized["height"],
        "finalized_block_id": finalized["block_id"],
        "snapshot_hash": snapshot_hash,
    }
    resp = StateSyncResponseMsg(
        header=_header(MsgType.STATE_SYNC_RESPONSE),
        ok=True,
        reason=None,
        height=10,
        snapshot=snapshot,
        snapshot_hash=snapshot_hash,
        snapshot_anchor=anchor,
    )
    svc = StateSyncService(
        chain_id="sync-semantic",
        schema_version="1",
        tx_index_hash="tx-index",
        state_provider=lambda: {},
    )

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_system_queue_invalid:system_queue_item_past_due_at_recovery",
    ):
        svc.verify_response(resp, trusted_anchor=anchor)

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_system_queue_invalid:system_queue_item_past_due_at_recovery",
    ):
        build_snapshot_anchor(state)


def test_state_sync_rejects_nontransferable_fields_even_with_projected_hash() -> None:
    state = state_sync_snapshot_view(_base_state())
    poisoned = dict(state)
    poisoned["created_ms"] = 123456
    projected = state_sync_snapshot_view(poisoned)
    snapshot_hash = sha256_hex_of(projected)
    anchor = build_snapshot_anchor(state)
    resp = StateSyncResponseMsg(
        header=_header(MsgType.STATE_SYNC_RESPONSE),
        ok=True,
        reason=None,
        height=int(state["height"]),
        snapshot=poisoned,
        snapshot_hash=snapshot_hash,
        snapshot_anchor=anchor,
    )
    svc = StateSyncService(
        chain_id="sync-semantic",
        schema_version="1",
        tx_index_hash="tx-index",
        state_provider=lambda: {},
    )

    with pytest.raises(StateSyncVerifyError, match="snapshot_contains_nontransferable_state"):
        svc.verify_response(resp, trusted_anchor=anchor)


@pytest.mark.parametrize("bad_due", [True, "11"])
def test_system_queue_rejects_coerced_due_height_types(bad_due: object) -> None:
    state = {"height": 10}
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=11,
        phase="pre",
    )
    state["system_queue"][0]["due_height"] = bad_due

    with pytest.raises(SystemQueueCorruptionError, match="system_queue_item_bad_due_height"):
        build_system_queue_lookup(state)
