from __future__ import annotations

import inspect

import pytest

from weall.net.codec import encode_message
from weall.net.messages import BftProposalMsg, MsgType, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport_memory import InMemoryTransport
from weall.net.transport_tcp import TcpTransport
from weall.net.transport_tls import TlsTransport
from weall.net.wire_limits import (
    MAX_BFT_BLOCK_BYTES,
    MAX_TRANSPORT_FRAME_BYTES,
    MAX_WIRE_MESSAGE_BYTES,
    WireSizeError,
    bft_block_limit_from_env,
)


def _cfg() -> NetConfig:
    return NetConfig(chain_id="wire-test", schema_version="1", tx_index_hash="0" * 64)


class _CaptureConn:
    peer_id = "peer"

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send(self, payload: bytes) -> None:
        self.sent.append(bytes(payload))

    def close(self) -> None:
        return None


def _proposal_with_encoded_size_at_most(limit: int) -> BftProposalMsg:
    header = WireHeader(
        type=MsgType.BFT_PROPOSAL,
        chain_id="wire-test",
        schema_version="1",
        tx_index_hash="0" * 64,
    )
    base = BftProposalMsg(header=header, view=1, proposer="@v1", block={"pad": ""})
    base_size = len(encode_message(base))
    pad = max(0, int(limit) - base_size)
    return BftProposalMsg(header=header, view=1, proposer="@v1", block={"pad": "x" * pad})


def test_one_canonical_default_drives_node_tcp_tls_and_bft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES", raising=False)
    assert PeerPolicy().max_packet_bytes == MAX_WIRE_MESSAGE_BYTES
    assert (
        inspect.signature(TcpTransport).parameters["max_frame_bytes"].default
        == MAX_TRANSPORT_FRAME_BYTES
    )
    assert (
        inspect.signature(TlsTransport).parameters["max_frame_bytes"].default
        == MAX_TRANSPORT_FRAME_BYTES
    )
    assert bft_block_limit_from_env() == MAX_BFT_BLOCK_BYTES
    assert 0 < MAX_BFT_BLOCK_BYTES < MAX_WIRE_MESSAGE_BYTES


def test_sender_accepts_max_and_rejects_one_byte_over_before_connection_send() -> None:
    node = NetNode(cfg=_cfg(), transport=InMemoryTransport())
    conn = _CaptureConn()
    node._conns["peer"] = conn  # focused sender boundary fixture
    node.send_bytes("peer", b"x" * MAX_WIRE_MESSAGE_BYTES)
    assert len(conn.sent) == 1
    with pytest.raises(WireSizeError):
        node.send_bytes("peer", b"x" * (MAX_WIRE_MESSAGE_BYTES + 1))
    assert len(conn.sent) == 1


def test_bft_wrapper_boundary_fails_locally_at_max_plus_one() -> None:
    node = NetNode(cfg=_cfg(), transport=InMemoryTransport())
    msg = _proposal_with_encoded_size_at_most(MAX_WIRE_MESSAGE_BYTES)
    raw = node.assert_message_fits(msg)
    assert len(raw) == MAX_WIRE_MESSAGE_BYTES
    too_large = BftProposalMsg(
        header=msg.header,
        view=msg.view,
        proposer=msg.proposer,
        block={"pad": str(msg.block["pad"]) + "x"},
    )
    with pytest.raises(WireSizeError):
        node.assert_message_fits(too_large)


def test_prod_rejects_local_limit_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    with pytest.raises(ValueError, match="production_peer_wire_limit_mismatch"):
        NetNode(
            cfg=_cfg(), peer_policy=PeerPolicy(max_packet_bytes=1024), transport=InMemoryTransport()
        )
    with pytest.raises(ValueError, match="production_tcp_frame_limit_mismatch"):
        TcpTransport(max_frame_bytes=1024)
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES", "1024")
    with pytest.raises(WireSizeError, match="production_bft_wire_limit_mismatch"):
        bft_block_limit_from_env()


def test_nonprod_can_lower_legacy_votecheck_limit_for_boundary_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES", "256")
    assert bft_block_limit_from_env() == 256
