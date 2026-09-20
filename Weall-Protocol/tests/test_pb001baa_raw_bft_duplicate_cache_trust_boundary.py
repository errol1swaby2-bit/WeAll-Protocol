from __future__ import annotations

import pytest

from weall.net.codec import encode_message
from weall.net.messages import (
    BftProposalMsg,
    BftQcMsg,
    BftTimeoutMsg,
    BftVoteMsg,
    MsgType,
    TxEnvelopeMsg,
    WireHeader,
)
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport import WirePacket


def _cfg() -> NetConfig:
    return NetConfig(
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="deadbeef",
        peer_id="local",
        bft_enabled=False,
    )


def _policy() -> PeerPolicy:
    return PeerPolicy(
        max_strikes=5,
        ban_cooldown_ms=10_000,
        duplicate_cache_entries=16,
        duplicate_cache_ttl_ms=15_000,
    )


def _header(kind: MsgType) -> WireHeader:
    return WireHeader(
        type=kind,
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="deadbeef",
    )


def _mark_established(node: NetNode, peer_id: str) -> None:
    rec = node._ensure_peer(peer_id)
    rec.router.handshake.status = "ESTABLISHED"
    rec.router.handshake.session_id = "pb001baa-session"


def _packet(peer_id: str, payload: bytes, *, received_at_ms: int) -> WirePacket:
    return WirePacket(
        peer_id=peer_id,
        payload=payload,
        received_at_ms=received_at_ms,
        meta=None,
    )


def _proposal() -> BftProposalMsg:
    return BftProposalMsg(
        header=_header(MsgType.BFT_PROPOSAL),
        view=7,
        proposer="@v1",
        block={
            "block_id": "b7",
            "block_hash": "hash-b7",
            "height": 7,
            "view": 7,
            "prev_block_id": "b6",
        },
        justify_qc=None,
    )


def _vote() -> BftVoteMsg:
    return BftVoteMsg(
        header=_header(MsgType.BFT_VOTE),
        view=7,
        vote={
            "t": "VOTE",
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "block_hash": "hash-b7",
            "parent_id": "b6",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
        },
    )


def _qc() -> BftQcMsg:
    return BftQcMsg(
        header=_header(MsgType.BFT_QC),
        qc={
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "block_hash": "hash-b7",
            "parent_id": "b6",
            "votes": [{"signer": "@v1"}],
        },
    )


def _timeout() -> BftTimeoutMsg:
    return BftTimeoutMsg(
        header=_header(MsgType.BFT_TIMEOUT),
        view=7,
        timeout={
            "t": "TIMEOUT",
            "chain_id": "chain-A",
            "view": 7,
            "high_qc_id": "b6",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
        },
    )


@pytest.mark.parametrize(
    ("kind", "message_factory", "handler_name"),
    [
        ("proposal", _proposal, "on_bft_proposal"),
        ("vote", _vote, "on_bft_vote"),
        ("qc", _qc, "on_bft_qc"),
        ("timeout", _timeout, "on_bft_timeout"),
    ],
)
def test_exact_bft_retry_reaches_trust_aware_handler_twice(
    kind: str,
    message_factory,
    handler_name: str,
) -> None:
    peer_id = "tcp://9.9.9.9:7777"
    delivered: list[str] = []
    kwargs = {handler_name: lambda _peer_id, _msg: delivered.append(kind)}
    node = NetNode(cfg=_cfg(), peer_policy=_policy(), **kwargs)
    _mark_established(node, peer_id)

    payload = encode_message(message_factory())
    node._handle_packet(_packet(peer_id, payload, received_at_ms=10_000))
    node._handle_packet(_packet(peer_id, payload, received_at_ms=10_100))

    assert delivered == [kind, kind]


def _tx(nonce: int) -> TxEnvelopeMsg:
    return TxEnvelopeMsg(
        header=_header(MsgType.TX_ENVELOPE),
        nonce=nonce,
        tx={
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": nonce,
            "payload": {"email": f"{nonce}@example.com"},
            "sig": "00",
            "chain_id": "chain-A",
        },
    )


def test_raw_duplicate_cache_fails_open_and_rebases_on_clock_rollback() -> None:
    peer_id = "tcp://8.8.8.8:8888"
    handled: list[int] = []
    node = NetNode(
        cfg=_cfg(),
        peer_policy=_policy(),
        on_tx=lambda _peer_id, msg: handled.append(int(msg.nonce)),
    )
    _mark_established(node, peer_id)

    payload = encode_message(_tx(1))
    node._handle_packet(_packet(peer_id, payload, received_at_ms=20_000))
    # Host clock moves backward. Abuse-hardening state must not suppress valid
    # traffic until the old wall-clock coordinate is reached again.
    node._handle_packet(_packet(peer_id, payload, received_at_ms=5_000))
    # Once rebased, the ordinary duplicate window is active again.
    node._handle_packet(_packet(peer_id, payload, received_at_ms=5_100))

    assert handled == [1, 1]
    peer = next(p for p in node.peers_debug()["peers"] if p["peer_id"] == peer_id)
    assert int(peer["duplicate_payloads_dropped"]) == 1


def test_non_bft_duplicate_suppression_remains_active_without_clock_rollback() -> None:
    peer_id = "tcp://7.7.7.7:7777"
    handled: list[int] = []
    node = NetNode(
        cfg=_cfg(),
        peer_policy=_policy(),
        on_tx=lambda _peer_id, msg: handled.append(int(msg.nonce)),
    )
    _mark_established(node, peer_id)

    payload = encode_message(_tx(2))
    node._handle_packet(_packet(peer_id, payload, received_at_ms=10_000))
    node._handle_packet(_packet(peer_id, payload, received_at_ms=10_100))

    assert handled == [2]
