from __future__ import annotations

from typing import Any

import pytest

from weall.net.messages import (
    BftProposalMsg,
    BftQcMsg,
    BftTimeoutMsg,
    BftVoteMsg,
    MsgType,
    TxEnvelopeMsg,
    WireHeader,
)
from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _DummyMempool:
    def peek(self, _n: int) -> list[dict[str, Any]]:
        return []

    def add(self, _tx: dict[str, Any], **_kwargs: Any) -> None:
        return None


class _Executor:
    chain_id = "chain-A"
    tx_index = None

    def snapshot(self) -> dict[str, Any]:
        return {}

    def read_state(self) -> dict[str, Any]:
        return {}

    def tx_index_hash(self) -> str:
        return "hash-A"

    def _schema_version(self) -> str:
        return "1"


def _loop() -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=_Executor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    loop._relay_cfg = lambda: object()  # type: ignore[method-assign]
    return loop


def _header(t: MsgType) -> WireHeader:
    return WireHeader(
        type=t,
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
    )


def _proposal() -> BftProposalMsg:
    return BftProposalMsg(
        header=_header(MsgType.BFT_PROPOSAL),
        view=1,
        proposer="v1",
        block={"block_id": "b1"},
        justify_qc=None,
    )


def _vote() -> BftVoteMsg:
    return BftVoteMsg(
        header=_header(MsgType.BFT_VOTE),
        view=1,
        vote={"t": "VOTE", "view": 1, "signer": "v1"},
    )


def _qc() -> BftQcMsg:
    return BftQcMsg(
        header=_header(MsgType.BFT_QC),
        qc={"t": "QC", "view": 1, "block_id": "b1"},
    )


def _timeout() -> BftTimeoutMsg:
    return BftTimeoutMsg(
        header=_header(MsgType.BFT_TIMEOUT),
        view=1,
        timeout={"t": "TIMEOUT", "view": 1, "signer": "v1"},
    )


def _tx() -> TxEnvelopeMsg:
    return TxEnvelopeMsg(
        header=_header(MsgType.TX_ENVELOPE),
        nonce=1,
        tx={"type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "payload": {}},
    )


def _env(relay_id: str = "rid-1") -> dict[str, Any]:
    return {
        "relay_id": relay_id,
        "sender_peer_id": "relay-peer",
    }


@pytest.mark.parametrize(
    ("message", "handler_name"),
    [
        (_proposal(), "_on_bft_proposal"),
        (_vote(), "_on_bft_vote"),
        (_qc(), "_on_bft_qc"),
        (_timeout(), "_on_bft_timeout"),
    ],
)
def test_rejected_bft_relay_stays_unacked_and_exact_retry_reaches_handler(
    monkeypatch: pytest.MonkeyPatch,
    message: object,
    handler_name: str,
) -> None:
    loop = _loop()
    calls: list[str] = []

    monkeypatch.setattr(
        "weall.net.net_loop.validate_relay_envelope",
        lambda envelope, *, cfg: dict(envelope),
    )
    monkeypatch.setattr("weall.net.net_loop.decode_relay_payload", lambda _env: message)
    monkeypatch.setattr(
        loop,
        handler_name,
        lambda _peer_id, _msg: calls.append("rejected") or False,
    )

    env = _env()
    assert loop._relay_process_envelope(env) is False
    assert env["relay_id"] not in loop._relay_seen

    assert loop._relay_process_envelope(env) is False
    assert calls == ["rejected", "rejected"]
    assert env["relay_id"] not in loop._relay_seen


def test_bft_relay_id_becomes_dedupable_only_after_authenticated_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = _loop()
    outcomes = iter((False, True))
    calls: list[str] = []

    monkeypatch.setattr(
        "weall.net.net_loop.validate_relay_envelope",
        lambda envelope, *, cfg: dict(envelope),
    )
    monkeypatch.setattr("weall.net.net_loop.decode_relay_payload", lambda _env: _proposal())

    def on_proposal(_peer_id: str, _msg: object) -> bool:
        calls.append("proposal")
        return next(outcomes)

    monkeypatch.setattr(loop, "_on_bft_proposal", on_proposal)

    env = _env()
    assert loop._relay_process_envelope(env) is False
    assert env["relay_id"] not in loop._relay_seen

    assert loop._relay_process_envelope(env) is True
    assert env["relay_id"] in loop._relay_seen

    # Once the exact artifact has crossed authenticated admission, an at-least-once
    # relay duplicate is safe to acknowledge without re-entering runtime.
    assert loop._relay_process_envelope(env) is True
    assert calls == ["proposal", "proposal"]


def test_relay_poll_does_not_ack_rejected_bft_then_acks_accepted_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = _loop()
    loop._relay_client_enabled = True
    loop._relay_urls = ["http://relay.example"]
    loop._relay_poll_ms = 1
    loop._relay_last_poll_ms = 0

    class _NodeCfg:
        peer_id = "node-b"

    class _Node:
        cfg = _NodeCfg()

    loop.node = _Node()  # type: ignore[assignment]

    env = _env()
    accepted = {"value": False}
    acks: list[list[str]] = []

    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: 10_000)
    monkeypatch.setattr(
        loop, "_relay_fetch", lambda _base, _peer_id: {"ok": True, "messages": [env]}
    )
    monkeypatch.setattr(loop, "_relay_ack", lambda _base, _peer_id, ids: acks.append(list(ids)))
    monkeypatch.setattr(
        "weall.net.net_loop.validate_relay_envelope",
        lambda envelope, *, cfg: dict(envelope),
    )
    monkeypatch.setattr("weall.net.net_loop.decode_relay_payload", lambda _env: _proposal())
    monkeypatch.setattr(
        loop,
        "_on_bft_proposal",
        lambda _peer_id, _msg: bool(accepted["value"]),
    )

    loop._relay_poll_tick()
    assert acks == [[]]

    accepted["value"] = True
    loop._relay_last_poll_ms = 0
    loop._relay_poll_tick()
    assert acks[-1] == ["rid-1"]


def test_non_bft_relay_keeps_existing_pre_dispatch_duplicate_suppression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = _loop()
    calls: list[str] = []

    monkeypatch.setattr(
        "weall.net.net_loop.validate_relay_envelope",
        lambda envelope, *, cfg: dict(envelope),
    )
    monkeypatch.setattr("weall.net.net_loop.decode_relay_payload", lambda _env: _tx())
    monkeypatch.setattr(loop, "_on_tx", lambda _peer_id, _msg: calls.append("tx"))

    env = _env("tx-rid")
    assert loop._relay_process_envelope(env) is True
    assert loop._relay_process_envelope(env) is True
    assert calls == ["tx"]
