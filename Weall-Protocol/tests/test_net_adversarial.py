# File: tests/test_net_adversarial.py
from __future__ import annotations

import pytest

from weall.net.codec import encode_message
from weall.net.messages import BlockVoteMsg, MsgType, PeerHello, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport import WirePacket


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="me")


def _pkt(peer_id: str, msg) -> WirePacket:
    return WirePacket(peer_id=peer_id, payload=encode_message(msg), received_at_ms=0, meta=None)


def test_protocol_mismatch_chain_id_fast_bans() -> None:
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=9, ban_cooldown_ms=10_000, fast_ban_mismatch_ms=60_000),
    )

    # Wrong chain_id -> handshake should reject and node should fast-ban for mismatch window.
    hdr_bad = WireHeader(
        type=MsgType.PEER_HELLO, chain_id="WRONG", schema_version="1", tx_index_hash="deadbeef"
    )
    hello_bad = PeerHello(
        header=hdr_bad, peer_id="tcp://9.9.9.9:7777", agent="t", nonce="n", caps=()
    )
    node._handle_packet(_pkt("tcp://9.9.9.9:7777", hello_bad))

    assert node.is_banned("tcp://9.9.9.9:7777")


def test_protocol_mismatch_schema_version_fast_bans() -> None:
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=9, ban_cooldown_ms=10_000, fast_ban_mismatch_ms=60_000),
    )

    hdr_bad = WireHeader(
        type=MsgType.PEER_HELLO, chain_id="test", schema_version="999", tx_index_hash="deadbeef"
    )
    hello_bad = PeerHello(
        header=hdr_bad, peer_id="tcp://1.2.3.4:5555", agent="t", nonce="n", caps=()
    )
    node._handle_packet(_pkt("tcp://1.2.3.4:5555", hello_bad))

    assert node.is_banned("tcp://1.2.3.4:5555")


def test_protocol_mismatch_tx_index_hash_fast_bans() -> None:
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=9, ban_cooldown_ms=10_000, fast_ban_mismatch_ms=60_000),
    )

    hdr_bad = WireHeader(
        type=MsgType.PEER_HELLO, chain_id="test", schema_version="1", tx_index_hash="BADHASH"
    )
    hello_bad = PeerHello(
        header=hdr_bad, peer_id="tcp://5.6.7.8:9999", agent="t", nonce="n", caps=()
    )
    node._handle_packet(_pkt("tcp://5.6.7.8:9999", hello_bad))

    assert node.is_banned("tcp://5.6.7.8:9999")


def test_identity_required_without_ledger_provider_bans_fast(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Require identity, but do not provide ledger_provider.
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "1")

    # Make first identity failure ban immediately.
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(
            max_strikes=1,
            ban_cooldown_ms=10_000,
            strike_handshake_rejected=1,
        ),
        ledger_provider=None,
    )

    hdr = WireHeader(
        type=MsgType.PEER_HELLO, chain_id="test", schema_version="1", tx_index_hash="deadbeef"
    )
    hello = PeerHello(
        header=hdr, peer_id="tcp://9.9.9.9:7777", agent="t", nonce="n", caps=(), identity={"x": 1}
    )
    node._handle_packet(_pkt("tcp://9.9.9.9:7777", hello))

    assert node.is_banned("tcp://9.9.9.9:7777")


def test_session_required_guard_is_enforced_without_handshake() -> None:
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=3, ban_cooldown_ms=10_000, strike_session_required=2),
    )

    hdr = WireHeader(
        type=MsgType.BLOCK_VOTE, chain_id="test", schema_version="1", tx_index_hash="deadbeef"
    )
    vote = BlockVoteMsg(header=hdr, height=1, block_hash="abc", vote="yes")

    node._handle_packet(_pkt("tcp://9.9.9.9:7777", vote))
    assert not node.is_banned("tcp://9.9.9.9:7777")

    node._handle_packet(_pkt("tcp://9.9.9.9:7777", vote))
    # 2 strikes per msg => 4 >= 3 => banned
    assert node.is_banned("tcp://9.9.9.9:7777")
