from __future__ import annotations

from weall.net.codec import encode_message
from weall.net.messages import MsgType, TxEnvelopeMsg, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport import WirePacket


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="me")


def _tx_msg(nonce: int, signer: str = "@alice") -> TxEnvelopeMsg:
    return TxEnvelopeMsg(
        header=WireHeader(
            type=MsgType.TX_ENVELOPE,
            chain_id="test",
            schema_version="1",
            tx_index_hash="deadbeef",
        ),
        nonce=nonce,
        tx={
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"email": f"{nonce}@example.com"},
            "sig": "00",
            "chain_id": "test",
        },
    )


def _pkt(peer_id: str, payload: bytes, *, received_at_ms: int) -> WirePacket:
    return WirePacket(peer_id=peer_id, payload=payload, received_at_ms=received_at_ms, meta=None)


def _mark_established(node: NetNode, peer_id: str) -> None:
    rec = node._ensure_peer(peer_id)
    rec.router.handshake.status = "ESTABLISHED"
    rec.router.handshake.session_id = "session-test"


def test_exact_duplicate_packet_is_suppressed_after_session_established_batch107() -> None:
    peer_id = "tcp://9.9.9.9:7777"
    handled: list[int] = []
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(
            max_strikes=5,
            ban_cooldown_ms=10_000,
            duplicate_cache_entries=8,
            duplicate_cache_ttl_ms=5_000,
        ),
        on_tx=lambda _peer_id, msg: handled.append(int(msg.nonce)),
    )
    _mark_established(node, peer_id)

    payload = encode_message(_tx_msg(1))
    node._handle_packet(_pkt(peer_id, payload, received_at_ms=1_100))
    node._handle_packet(_pkt(peer_id, payload, received_at_ms=1_200))

    assert handled == [1]
    dbg = node.peers_debug()
    peer = next(p for p in dbg["peers"] if p["peer_id"] == peer_id)
    assert int(peer["duplicate_payloads_dropped"]) == 1
    assert int(peer["duplicate_payload_cache_size"]) == 1
    assert int(peer["strikes"]) == 0


def test_duplicate_cache_respects_ttl_and_capacity_batch107() -> None:
    peer_id = "tcp://8.8.8.8:8888"
    handled: list[int] = []
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(
            max_strikes=5,
            ban_cooldown_ms=10_000,
            duplicate_cache_entries=1,
            duplicate_cache_ttl_ms=5_000,
        ),
        on_tx=lambda _peer_id, msg: handled.append(int(msg.nonce)),
    )
    _mark_established(node, peer_id)

    tx_a = encode_message(_tx_msg(1))
    tx_b = encode_message(_tx_msg(2))

    node._handle_packet(_pkt(peer_id, tx_a, received_at_ms=1_100))
    node._handle_packet(_pkt(peer_id, tx_b, received_at_ms=1_200))
    # tx_a should have been evicted because capacity is 1.
    node._handle_packet(_pkt(peer_id, tx_a, received_at_ms=1_300))
    # Now an immediate repeat of tx_a should be suppressed.
    node._handle_packet(_pkt(peer_id, tx_a, received_at_ms=1_400))
    # After TTL expiry, tx_a is accepted again.
    node._handle_packet(_pkt(peer_id, tx_a, received_at_ms=7_000))

    assert handled == [1, 2, 1, 1]
    dbg = node.peers_debug()
    peer = next(p for p in dbg["peers"] if p["peer_id"] == peer_id)
    assert int(peer["duplicate_payloads_dropped"]) == 1
    assert int(peer["duplicate_payload_cache_size"]) <= 1
