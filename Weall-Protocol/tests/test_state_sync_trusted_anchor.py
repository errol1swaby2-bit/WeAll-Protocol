from __future__ import annotations

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor
from weall.runtime.state_hash import compute_state_root


def _hdr() -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c1",
    )


def test_snapshot_response_contains_authenticated_anchor() -> None:
    st = {"height": 7, "tip_hash": "abc123", "accounts": {"a": {"nonce": 1}}, "finalized": {"height": 6, "block_id": "b6"}}
    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)
    req = StateSyncRequestMsg(header=_hdr(), mode="snapshot", selector=None)
    resp = svc.handle_request(req)

    assert resp.ok is True
    assert resp.snapshot_anchor is not None
    assert resp.snapshot_anchor["height"] == 7
    assert resp.snapshot_anchor["tip_hash"] == "abc123"
    assert resp.snapshot_anchor["state_root"] == compute_state_root(st)
    svc.verify_response(resp)


def test_snapshot_request_can_pin_trusted_anchor() -> None:
    st = {"height": 11, "tip_hash": "tip11", "accounts": {"a": {"nonce": 2}}, "finalized": {"height": 10, "block_id": "b10"}}
    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)
    anchor = build_snapshot_anchor(st)
    req = StateSyncRequestMsg(header=_hdr(), mode="snapshot", selector={"trusted_anchor": anchor})
    resp = svc.handle_request(req)
    assert resp.ok is True
    svc.verify_response(resp, trusted_anchor=anchor)


def test_snapshot_request_rejects_mismatched_trusted_anchor() -> None:
    st = {"height": 11, "tip_hash": "tip11", "accounts": {"a": {"nonce": 2}}, "finalized": {"height": 10, "block_id": "b10"}}
    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)
    bad_anchor = {"height": 11, "tip_hash": "evil-tip"}
    req = StateSyncRequestMsg(header=_hdr(), mode="snapshot", selector={"trusted_anchor": bad_anchor})
    resp = svc.handle_request(req)
    assert resp.ok is False
    assert resp.reason == "trusted_anchor_mismatch"


def test_verify_response_rejects_tampered_snapshot_anchor() -> None:
    st = {"height": 7, "tip_hash": "abc123", "accounts": {"a": {"nonce": 1}}, "finalized": {"height": 6, "block_id": "b6"}}
    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)
    req = StateSyncRequestMsg(header=_hdr(), mode="snapshot", selector=None)
    resp = svc.handle_request(req)
    assert resp.snapshot_anchor is not None
    tampered = resp.__class__(
        header=resp.header,
        ok=resp.ok,
        reason=resp.reason,
        height=resp.height,
        snapshot=resp.snapshot,
        snapshot_hash=resp.snapshot_hash,
        snapshot_anchor={**resp.snapshot_anchor, "tip_hash": "evil-tip"},
        blocks=resp.blocks,
    )
    with pytest.raises(StateSyncVerifyError, match="snapshot_anchor_mismatch:tip_hash"):
        svc.verify_response(tampered)
