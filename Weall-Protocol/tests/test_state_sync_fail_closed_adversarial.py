from __future__ import annotations

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import (
    StateSyncService,
    StateSyncVerifyError,
    build_snapshot_anchor,
    sha256_hex_of,
)


def _req_hdr() -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c1",
    )


def _resp_hdr() -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_RESPONSE,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c1",
    )


def test_verify_response_rejects_header_chain_mismatch() -> None:
    st = {"height": 3, "tip_hash": "t3", "accounts": {"a": {"nonce": 1}}}
    svc = StateSyncService(
        chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st
    )
    req = StateSyncRequestMsg(header=_req_hdr(), mode="snapshot", selector=None)
    resp = svc.handle_request(req)
    bad = StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id="evil",
            schema_version="1",
            tx_index_hash="deadbeef",
            corr_id="c1",
        ),
        ok=resp.ok,
        reason=resp.reason,
        height=resp.height,
        snapshot=resp.snapshot,
        snapshot_hash=resp.snapshot_hash,
        snapshot_anchor=resp.snapshot_anchor,
        blocks=resp.blocks,
    )
    with pytest.raises(StateSyncVerifyError, match="bad_response_header:chain_id"):
        svc.verify_response(bad)


def test_verify_delta_response_rejects_mismatched_trusted_anchor() -> None:
    st = {"height": 5, "tip_hash": "b5", "accounts": {"a": {"nonce": 1}}}
    blocks = {
        4: {"height": 4, "block_id": "b4", "prev_block_hash": "b3"},
        5: {"height": 5, "block_id": "b5", "prev_block_hash": "b4"},
    }
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: st,
        block_provider=lambda h: blocks.get(h),
    )
    anchor = build_snapshot_anchor(st)
    req = StateSyncRequestMsg(
        header=_req_hdr(),
        mode="delta",
        from_height=3,
        to_height=5,
        selector={"trusted_anchor": anchor},
    )
    resp = svc.handle_request(req)
    assert resp.ok is True
    bad_anchor = {**anchor, "tip_hash": "evil"}
    with pytest.raises(StateSyncVerifyError, match="trusted_anchor_mismatch"):
        svc.verify_response(resp, trusted_anchor=bad_anchor)


def test_verify_delta_response_rejects_height_beyond_response_height() -> None:
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: {"height": 2},
    )
    resp = StateSyncResponseMsg(
        header=_resp_hdr(),
        ok=True,
        reason=None,
        height=4,
        snapshot=None,
        snapshot_hash=None,
        snapshot_anchor={"height": 4},
        blocks=(
            {"height": 4, "block_id": "b4", "prev_block_hash": "b3"},
            {"height": 5, "block_id": "b5", "prev_block_hash": "b4"},
        ),
    )
    with pytest.raises(StateSyncVerifyError, match="block_height_exceeds_response_height"):
        svc.verify_response(resp)


def test_verify_snapshot_rejects_missing_anchor_when_trusted_anchor_supplied() -> None:
    st = {"height": 2, "tip_hash": "t2", "accounts": {"a": {"nonce": 1}}}
    svc = StateSyncService(
        chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st
    )
    snapshot_hash = sha256_hex_of(st)
    trusted_anchor = build_snapshot_anchor(st)
    resp = StateSyncResponseMsg(
        header=_resp_hdr(),
        ok=True,
        reason=None,
        height=2,
        snapshot=st,
        snapshot_hash=snapshot_hash,
        snapshot_anchor=None,
        blocks=(),
    )
    with pytest.raises(StateSyncVerifyError, match="missing_snapshot_anchor"):
        svc.verify_response(resp, trusted_anchor=trusted_anchor)
