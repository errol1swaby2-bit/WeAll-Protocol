from __future__ import annotations

from weall.net.codec import encode_message
from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport import PeerAddr
from weall.net.transport_memory import InMemoryTransport


def _cfg(peer_id: str) -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id=peer_id)


def _handshake(*nodes: NetNode) -> None:
    for _ in range(6):
        for node in nodes:
            node.tick()


def _resp(corr_id: str, *, height: int = 3) -> StateSyncResponseMsg:
    return StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
            corr_id=corr_id,
        ),
        ok=True,
        reason=None,
        height=height,
        snapshot={"height": height, "tip_hash": f"b{height}", "accounts": {}},
        snapshot_hash="ignored-by-transport-tests",
        snapshot_anchor={"height": height},
        blocks=(),
    )


def test_unsolicited_state_sync_response_is_dropped() -> None:
    a = NetNode(cfg=_cfg("peer-a"), transport=InMemoryTransport())
    b = NetNode(cfg=_cfg("peer-b"), transport=InMemoryTransport())
    a.bind(PeerAddr("mem://a"))
    b.bind(PeerAddr("mem://b"))
    a.connect(PeerAddr("mem://b"))
    b.connect(PeerAddr("mem://a"))
    _handshake(a, b)

    b.send_message("mem://a", _resp("unsolicited-1"))
    a.tick()

    assert a.pop_sync_response("unsolicited-1") is None
    peers = {p["peer_id"]: p for p in a.peers_debug()["peers"]}
    assert peers["mem://b"]["sync_unsolicited_dropped"] == 1
    assert peers["mem://b"]["sync_replayed_dropped"] == 0

    a.close()
    b.close()


def test_state_sync_response_must_match_expected_peer() -> None:
    a = NetNode(cfg=_cfg("peer-a"), transport=InMemoryTransport())
    b = NetNode(cfg=_cfg("peer-b"), transport=InMemoryTransport())
    c = NetNode(cfg=_cfg("peer-c"), transport=InMemoryTransport())
    a.bind(PeerAddr("mem://a"))
    b.bind(PeerAddr("mem://b"))
    c.bind(PeerAddr("mem://c"))
    a.connect(PeerAddr("mem://b"))
    b.connect(PeerAddr("mem://a"))
    a.connect(PeerAddr("mem://c"))
    c.connect(PeerAddr("mem://a"))
    _handshake(a, b, c)

    a._register_sync_request("mem://b", "corr-1", deadline_ms=10**12)

    c.send_message("mem://a", _resp("corr-1"))
    a.tick()
    assert a.pop_sync_response("corr-1") is None

    b.send_message("mem://a", _resp("corr-1"))
    a.tick()
    resp = a.pop_sync_response("corr-1")
    assert resp is not None
    assert resp.header.corr_id == "corr-1"

    peers = {p["peer_id"]: p for p in a.peers_debug()["peers"]}
    assert peers["mem://c"]["sync_unsolicited_dropped"] == 1
    assert peers["mem://b"]["sync_unsolicited_dropped"] == 0

    a.close()
    b.close()
    c.close()


def test_replayed_state_sync_response_is_dropped_after_completion() -> None:
    a = NetNode(cfg=_cfg("peer-a"), transport=InMemoryTransport())
    b = NetNode(cfg=_cfg("peer-b"), transport=InMemoryTransport())
    a.bind(PeerAddr("mem://a"))
    b.bind(PeerAddr("mem://b"))
    a.connect(PeerAddr("mem://b"))
    b.connect(PeerAddr("mem://a"))
    _handshake(a, b)

    a._register_sync_request("mem://b", "corr-2", deadline_ms=10**12)
    b.send_message("mem://a", _resp("corr-2", height=3))
    a.tick()
    assert a.pop_sync_response("corr-2") is not None

    b.send_message("mem://a", _resp("corr-2", height=4))
    a.tick()
    assert a.pop_sync_response("corr-2") is None

    peers = {p["peer_id"]: p for p in a.peers_debug()["peers"]}
    assert peers["mem://b"]["sync_replayed_dropped"] == 1
    assert peers["mem://b"]["sync_responses_dropped"] >= 1

    a.close()
    b.close()


def test_outstanding_state_sync_requests_are_bounded() -> None:
    a = NetNode(
        cfg=_cfg("peer-a"),
        transport=InMemoryTransport(),
        peer_policy=PeerPolicy(max_outstanding_sync_requests=2, sync_request_ttl_ms=5_000),
    )
    a.bind(PeerAddr("mem://a"))

    a._register_sync_request("mem://b", "corr-1", deadline_ms=10**12)
    a._register_sync_request("mem://b", "corr-2", deadline_ms=10**12)
    a._register_sync_request("mem://b", "corr-3", deadline_ms=10**12)

    assert "corr-1" not in a._sync_requests
    assert tuple(a._sync_requests.keys()) == ("corr-2", "corr-3")
    counts = a.peers_debug()["counts"]
    assert counts["sync_requests_outstanding"] == 2
    assert counts["sync_outstanding_capacity"] == 2

    a.close()
