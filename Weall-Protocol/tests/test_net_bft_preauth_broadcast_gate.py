"""Broadcasts must never outrun an authenticated P2P session on TCP rejoin."""

from __future__ import annotations

import pytest

from weall.net.messages import BftQcMsg, MsgType, WireHeader
from weall.net.node import NetConfig, NetNode
from weall.net.transport_memory import InMemoryTransport


class _CaptureConnection:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send(self, payload: bytes) -> None:
        self.sent.append(bytes(payload))


def test_bft_broadcast_skips_preauth_and_unverified_connections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = NetNode(
        cfg=NetConfig(chain_id="broadcast-gate", schema_version="1", tx_index_hash="0" * 64),
        transport=InMemoryTransport(),
    )
    preauth = node._ensure_peer("tcp://127.0.0.1:41001")
    ready = node._ensure_peer("tcp://127.0.0.1:41002")
    preauth_conn = _CaptureConnection()
    ready_conn = _CaptureConnection()
    node._conns[preauth.peer_id] = preauth_conn
    node._conns[ready.peer_id] = ready_conn

    ready.router.handshake.status = "ESTABLISHED"
    ready.router.handshake.session_id = "authenticated-session"
    monkeypatch.setattr(node, "_identity_required", lambda: True)

    message = BftQcMsg(
        header=WireHeader(
            type=MsgType.BFT_QC,
            chain_id="broadcast-gate",
            schema_version="1",
            tx_index_hash="0" * 64,
        ),
        qc={"t": "QC", "block_id": "validated-elsewhere"},
    )

    # Neither a raw TCP connection nor an established but unverified
    # identity may receive an application/consensus broadcast.
    node.broadcast_message(message)
    assert preauth_conn.sent == []
    assert ready_conn.sent == []

    ready.identity_ok = True
    node.broadcast_message(message)
    assert preauth_conn.sent == []
    assert len(ready_conn.sent) == 1

    ready.banned_until_ms = 99_999_999_999_999
    node.broadcast_message(message)
    assert preauth_conn.sent == []
    assert len(ready_conn.sent) == 1
