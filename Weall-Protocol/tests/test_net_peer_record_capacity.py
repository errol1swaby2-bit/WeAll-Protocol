from __future__ import annotations

from weall.net.codec import encode_message
from weall.net.messages import MsgType, PeerHello, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport import WirePacket
from weall.runtime.protocol_profile import runtime_protocol_profile_hash, runtime_protocol_version


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="me")


def _hello_pkt(peer_id: str, *, received_at_ms: int) -> WirePacket:
    hdr = WireHeader(
        type=MsgType.PEER_HELLO,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
    )
    hello = PeerHello(
        header=hdr,
        peer_id=peer_id,
        agent="t",
        nonce=f"n-{peer_id}",
        caps=(),
        protocol_version=runtime_protocol_version(),
        protocol_profile_hash=runtime_protocol_profile_hash(),
    )
    return WirePacket(
        peer_id=peer_id, payload=encode_message(hello), received_at_ms=received_at_ms, meta=None
    )


def test_peer_record_capacity_evicts_oldest_unestablished_peer_batch108() -> None:
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=3, ban_cooldown_ms=10_000, max_peer_records=2),
    )

    # First peer never establishes because the packet is undecodable.
    node._handle_packet(
        WirePacket(peer_id="peer-a", payload=b"not-json", received_at_ms=1, meta=None)
    )
    assert "peer-a" in node._peers

    # Two valid handshakes arrive; the oldest unestablished record should be evicted.
    node._handle_packet(_hello_pkt("peer-b", received_at_ms=2))
    node._handle_packet(_hello_pkt("peer-c", received_at_ms=3))

    assert "peer-a" not in node._peers
    assert sorted(node._peers.keys()) == ["peer-b", "peer-c"]

    dbg = node.peers_debug()
    assert int(dbg["counts"]["peers_total"]) == 2
    assert int(dbg["counts"]["peer_record_capacity"]) == 2


def test_peer_record_capacity_preserves_established_session_batch108() -> None:
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=3, ban_cooldown_ms=10_000, max_peer_records=2),
    )

    # Established peer must survive later peer churn.
    node._handle_packet(_hello_pkt("peer-established", received_at_ms=10))
    assert node._peers["peer-established"].router.handshake.is_established() is True

    node._handle_packet(
        WirePacket(peer_id="peer-transient", payload=b"bad", received_at_ms=11, meta=None)
    )
    assert "peer-transient" in node._peers

    node._handle_packet(_hello_pkt("peer-new", received_at_ms=12))

    assert "peer-established" in node._peers
    assert "peer-new" in node._peers
    assert "peer-transient" not in node._peers

    dbg = node.peers_debug()
    peers = {p["peer_id"]: p for p in dbg["peers"]}
    assert int(peers["peer-established"]["packets_received"]) >= 1
    assert int(peers["peer-established"]["established_at_ms"]) > 0
    assert int(peers["peer-established"]["last_seen_ms"]) >= 10
