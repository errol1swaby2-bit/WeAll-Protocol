from __future__ import annotations

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, build_snapshot_anchor


def _hdr() -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c1",
    )


def _block(height: int) -> dict:
    return {
        "height": height,
        "block_id": f"b{height}",
        "parent_block_id": "" if height <= 1 else f"b{height - 1}",
    }


def test_delta_request_rejects_from_height_beyond_tip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", raising=False)
    st = {
        "height": 3,
        "tip_hash": "tip3",
        "accounts": {},
        "finalized": {"height": 3, "block_id": "b3"},
    }
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: st,
        block_provider=lambda h: _block(h),
    )

    resp = svc.handle_request(StateSyncRequestMsg(header=_hdr(), mode="delta", from_height=4))

    assert resp.ok is False
    assert resp.reason == "bad_from_height"


def test_delta_request_rejects_to_height_below_from_height() -> None:
    st = {
        "height": 5,
        "tip_hash": "tip5",
        "accounts": {},
        "finalized": {"height": 5, "block_id": "b5"},
    }
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: st,
        block_provider=lambda h: _block(h),
    )

    resp = svc.handle_request(
        StateSyncRequestMsg(header=_hdr(), mode="delta", from_height=4, to_height=3)
    )

    assert resp.ok is False
    assert resp.reason == "bad_height_range"


def test_delta_request_caps_served_blocks_at_local_finalized_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    st = {
        "height": 5,
        "tip_hash": "tip5",
        "accounts": {},
        "finalized": {"height": 3, "block_id": "b3"},
    }
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: st,
        block_provider=lambda h: _block(h),
    )
    anchor = build_snapshot_anchor(st)

    resp = svc.handle_request(
        StateSyncRequestMsg(
            header=_hdr(),
            mode="delta",
            from_height=0,
            to_height=5,
            selector={"trusted_anchor": anchor},
        )
    )

    assert resp.ok is True
    assert [int(b.get("height") or 0) for b in resp.blocks] == [1, 2, 3]
    assert resp.snapshot is None


def test_delta_request_rejects_range_starting_past_finalized_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    st = {
        "height": 5,
        "tip_hash": "tip5",
        "accounts": {},
        "finalized": {"height": 3, "block_id": "b3"},
    }
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: st,
        block_provider=lambda h: _block(h),
    )
    anchor = build_snapshot_anchor(st)

    resp = svc.handle_request(
        StateSyncRequestMsg(
            header=_hdr(),
            mode="delta",
            from_height=3,
            to_height=5,
            selector={"trusted_anchor": anchor},
        )
    )

    assert resp.ok is False
    assert resp.reason == "delta_range_exceeds_finalized_anchor"
