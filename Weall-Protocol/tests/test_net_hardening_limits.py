from __future__ import annotations

from weall.net.codec import encode_message
from weall.net.messages import MsgType, PeerHello, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport import WirePacket


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="me")


def test_oversize_packet_counts_as_decode_strike_and_bans_on_threshold() -> None:
    pol = PeerPolicy(max_strikes=2, ban_cooldown_ms=10_000, max_packet_bytes=10)
    node = NetNode(cfg=_cfg(), peer_policy=pol)

    big = WirePacket(peer_id="tcp://1.2.3.4:5555", payload=b"x" * 11, received_at_ms=0, meta=None)
    node._handle_packet(big)
    assert not node.is_banned(big.peer_id)
    node._handle_packet(big)
    assert node.is_banned(big.peer_id)


def test_rate_limit_strikes_and_can_ban() -> None:
    # Allow exactly 1 message immediately; everything after is rate-limited.
    pol = PeerPolicy(
        max_strikes=2,
        ban_cooldown_ms=10_000,
        rate_msgs_per_sec=0,  # no refill
        burst_msgs=1,
        rate_bytes_per_sec=0,
        burst_bytes=10_000,
        strike_rate_limited=1,
    )
    node = NetNode(cfg=_cfg(), peer_policy=pol)

    hdr = WireHeader(type=MsgType.PEER_HELLO, chain_id="test", schema_version="1", tx_index_hash="deadbeef")
    hello = PeerHello(header=hdr, peer_id="tcp://9.9.9.9:7777", agent="t", nonce="n", caps=())
    pkt = WirePacket(peer_id="tcp://9.9.9.9:7777", payload=encode_message(hello), received_at_ms=0, meta=None)

    # First passes.
    node._handle_packet(pkt)
    assert not node.is_banned(pkt.peer_id)

    # Next two are rate-limited => 2 strikes => ban.
    node._handle_packet(pkt)
    assert not node.is_banned(pkt.peer_id)
    node._handle_packet(pkt)
    assert node.is_banned(pkt.peer_id)
