from __future__ import annotations

from weall.net.codec import encode_message
from weall.net.messages import MsgType, WireHeader, BlockVoteMsg, StateSyncRequestMsg
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.state_sync import StateSyncService, sha256_hex_of
from weall.net.transport import WirePacket


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="me")


def _pkt(peer_id: str, msg) -> WirePacket:
    return WirePacket(peer_id=peer_id, payload=encode_message(msg), received_at_ms=0, meta=None)


def test_peer_eviction_on_decode_fail() -> None:
    node = NetNode(cfg=_cfg(), peer_policy=PeerPolicy(max_strikes=2, ban_cooldown_ms=10_000))

    bad = WirePacket(peer_id="tcp://1.2.3.4:5555", payload=b"not-json", received_at_ms=0, meta=None)
    node._handle_packet(bad)
    assert not node.is_banned(bad.peer_id)
    node._handle_packet(bad)
    assert node.is_banned(bad.peer_id)


def test_session_required_strikes_and_ban() -> None:
    node = NetNode(cfg=_cfg(), peer_policy=PeerPolicy(max_strikes=3, ban_cooldown_ms=10_000, strike_session_required=2))

    # Send a post-handshake message without doing handshake -> should be SessionRequired
    hdr = WireHeader(type=MsgType.BLOCK_VOTE, chain_id="test", schema_version="1", tx_index_hash="deadbeef")
    vote = BlockVoteMsg(header=hdr, height=1, block_hash="abc", vote="yes")
    node._handle_packet(_pkt("tcp://9.9.9.9:7777", vote))
    node._handle_packet(_pkt("tcp://9.9.9.9:7777", vote))
    # 2 strikes per msg => 4 >= 3 => banned
    assert node.is_banned("tcp://9.9.9.9:7777")


def test_state_sync_snapshot_hash_verifies() -> None:
    st = {"height": 7, "tip": "x", "accounts": {"a": {"nonce": 1}}}

    svc = StateSyncService(chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st)

    hdr = WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c",
    )
    req = StateSyncRequestMsg(header=hdr, mode="snapshot", from_height=0, to_height=None, selector=None)
    resp = svc.handle_request(req)

    assert resp.ok is True
    assert resp.snapshot is not None
    assert resp.snapshot_hash == sha256_hex_of(st)
    # verify should not raise
    svc.verify_response(resp)
