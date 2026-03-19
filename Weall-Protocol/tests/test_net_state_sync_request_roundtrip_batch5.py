from __future__ import annotations

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.node import NetConfig, NetNode
from weall.net.state_sync import StateSyncService, build_snapshot_anchor
from weall.net.transport import PeerAddr
from weall.net.transport_memory import InMemoryTransport


def _cfg(peer_id: str) -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id=peer_id)


def _handshake(a: NetNode, b: NetNode) -> None:
    a.connect(PeerAddr("mem://b"))
    b.connect(PeerAddr("mem://a"))
    for _ in range(6):
        a.tick()
        b.tick()


def _req(corr_id: str, *, mode: str, from_height: int = 0, to_height: int | None = None, selector=None) -> StateSyncRequestMsg:
    return StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            corr_id=corr_id,
        ),
        mode=mode,
        from_height=from_height,
        to_height=to_height,
        selector=selector,
    )


def test_request_state_sync_snapshot_roundtrip_over_transport() -> None:
    st = {"height": 3, "tip_hash": "b3", "accounts": {"a": {"nonce": 1}}}

    a = NetNode(cfg=_cfg("peer-a"), transport=InMemoryTransport())
    b = NetNode(
        cfg=_cfg("peer-b"),
        transport=InMemoryTransport(),
        sync_service=StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st),
    )
    a.bind(PeerAddr("mem://a"))
    b.bind(PeerAddr("mem://b"))
    _handshake(a, b)

    req = _req("snap-1", mode="snapshot")
    resp = a.request_state_sync("mem://b", req, timeout_ms=500, pump=lambda: (b.tick(), a.tick()), sleep_ms=0)
    assert resp is not None
    assert resp.ok is True
    assert resp.snapshot == st

    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)
    svc.verify_response(resp)

    a.close()
    b.close()


def test_request_state_sync_delta_roundtrip_over_transport() -> None:
    st = {"height": 3, "tip_hash": "b3", "accounts": {"a": {"nonce": 1}}}
    blocks = {
        2: {"height": 2, "block_id": "b2", "prev_block_hash": "b1"},
        3: {"height": 3, "block_id": "b3", "prev_block_hash": "b2"},
    }

    a = NetNode(cfg=_cfg("peer-a"), transport=InMemoryTransport())
    b = NetNode(
        cfg=_cfg("peer-b"),
        transport=InMemoryTransport(),
        sync_service=StateSyncService(
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            state_provider=lambda: st,
            block_provider=lambda h: blocks.get(h),
        ),
    )
    a.bind(PeerAddr("mem://a"))
    b.bind(PeerAddr("mem://b"))
    _handshake(a, b)

    anchor = build_snapshot_anchor(st)
    req = _req("delta-1", mode="delta", from_height=1, to_height=3, selector={"trusted_anchor": anchor})
    resp = a.request_state_sync("mem://b", req, timeout_ms=500, pump=lambda: (b.tick(), a.tick()), sleep_ms=0)
    assert resp is not None
    assert resp.ok is True
    assert tuple(resp.blocks) == (blocks[2], blocks[3])

    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)
    svc.verify_response(resp, trusted_anchor=anchor)

    a.close()
    b.close()


def test_request_state_sync_partition_then_rejoin_retry_succeeds() -> None:
    st = {"height": 2, "tip_hash": "b2", "accounts": {"a": {"nonce": 1}}}

    a = NetNode(cfg=_cfg("peer-a"), transport=InMemoryTransport())
    b = NetNode(
        cfg=_cfg("peer-b"),
        transport=InMemoryTransport(),
        sync_service=StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st),
    )
    a.bind(PeerAddr("mem://a"))
    b.bind(PeerAddr("mem://b"))
    _handshake(a, b)

    req1 = _req("snap-timeout", mode="snapshot")
    resp1 = a.request_state_sync("mem://b", req1, timeout_ms=25, pump=lambda: a.tick(), sleep_ms=0)
    assert resp1 is None

    req2 = _req("snap-rejoin", mode="snapshot")
    resp2 = a.request_state_sync("mem://b", req2, timeout_ms=500, pump=lambda: (b.tick(), a.tick()), sleep_ms=0)
    assert resp2 is not None
    assert resp2.ok is True
    assert resp2.snapshot == st

    a.close()
    b.close()
