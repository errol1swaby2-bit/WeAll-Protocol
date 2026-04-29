from __future__ import annotations

from weall.net.codec import encode_message
from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.state_sync import StateSyncService, build_snapshot_anchor
from weall.net.transport import WirePacket


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="me")


def _pkt(peer_id: str, msg) -> WirePacket:
    return WirePacket(peer_id=peer_id, payload=encode_message(msg), received_at_ms=0, meta=None)


def test_state_sync_request_with_mismatched_header_fast_bans_peer() -> None:
    st = {"height": 3, "tip_hash": "t3", "accounts": {"a": {"nonce": 1}}}
    svc = StateSyncService(
        chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st
    )
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=2, ban_cooldown_ms=10_000, strike_handshake_rejected=1),
        sync_service=svc,
    )

    hello_hdr = WireHeader(
        type=MsgType.PEER_HELLO, chain_id="test", schema_version="1", tx_index_hash="deadbeef"
    )
    from weall.net.messages import PeerHello

    node._handle_packet(
        _pkt(
            "tcp://1.2.3.4:5555",
            PeerHello(
                header=hello_hdr, peer_id="tcp://1.2.3.4:5555", agent="t", nonce="n", caps=()
            ),
        )
    )

    bad_hdr = WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="WRONG",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c1",
    )
    req = StateSyncRequestMsg(header=bad_hdr, mode="snapshot", selector=None)
    node._handle_packet(_pkt("tcp://1.2.3.4:5555", req))
    node._handle_packet(_pkt("tcp://1.2.3.4:5555", req))
    assert node.is_banned("tcp://1.2.3.4:5555")


def test_state_sync_service_requires_pinned_anchor_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    st = {"height": 4, "tip_hash": "t4", "accounts": {"a": {"nonce": 1}}}
    svc = StateSyncService(
        chain_id="test", schema_version="1", tx_index_hash="deadbeef", state_provider=lambda: st
    )
    hdr = WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c1",
    )
    req = StateSyncRequestMsg(header=hdr, mode="snapshot", selector=None)
    resp = svc.handle_request(req)
    assert resp.ok is False
    assert resp.reason == "trusted_anchor_required"

    anchor = build_snapshot_anchor(st)
    req2 = StateSyncRequestMsg(header=hdr, mode="snapshot", selector={"trusted_anchor": anchor})
    resp2 = svc.handle_request(req2)
    assert resp2.ok is True
