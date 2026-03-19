from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.messages import BftTimeoutMsg, BftVoteMsg, MsgType, WireHeader
from weall.net.net_loop import BftInboundProcessingError, NetLoopConfig, NetMeshLoop


class _FakeNode:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(peer_id="local-peer", chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef")
        self.calls = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


class _FakeMempool:
    def read_all(self):
        return []


class _VoteExecutorQcApply:
    def __init__(self) -> None:
        self.applied_qcs = []

    def bft_on_vote(self, vote):
        return {
            "chain_id": "chain-A",
            "view": int(vote.get("view") or 0),
            "block_id": str(vote.get("block_id") or ""),
            "parent_id": str(vote.get("parent_id") or ""),
            "votes": [vote],
        }

    def bft_on_qc(self, qc):
        self.applied_qcs.append(dict(qc))
        return {"ok": True}


class _TimeoutExecutorQcApply:
    def __init__(self) -> None:
        self.applied_qcs = []

    def bft_on_timeout(self, timeout):
        return {
            "chain_id": "chain-A",
            "view": int(timeout.get("view") or 0),
            "block_id": str(timeout.get("high_qc_id") or ""),
            "parent_id": "b5",
            "votes": [{"signer": str(timeout.get("signer") or "")}],
        }

    def bft_on_qc(self, qc):
        self.applied_qcs.append(dict(qc))
        return {"ok": True}


class _VoteExecutorQcApplyBoom(_VoteExecutorQcApply):
    def bft_on_qc(self, qc):
        raise RuntimeError("qc apply boom")


class _TimeoutExecutorQcApplyBoom(_TimeoutExecutorQcApply):
    def bft_on_qc(self, qc):
        raise RuntimeError("qc apply boom")


def _mk_loop(executor) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=_FakeMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode()
    loop._bft_enabled = True
    return loop


def _vote_msg() -> BftVoteMsg:
    return BftVoteMsg(
        header=WireHeader(type=MsgType.BFT_VOTE, chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef"),
        view=7,
        vote={
            "t": "VOTE",
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "parent_id": "b6",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
        },
    )


def _timeout_msg() -> BftTimeoutMsg:
    return BftTimeoutMsg(
        header=WireHeader(type=MsgType.BFT_TIMEOUT, chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef"),
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


def test_vote_formed_qc_is_applied_locally_before_broadcast() -> None:
    ex = _VoteExecutorQcApply()
    loop = _mk_loop(ex)
    loop._on_bft_vote("peer-a", _vote_msg())
    assert len(ex.applied_qcs) == 1
    assert ex.applied_qcs[0]["block_id"] == "b7"
    assert len(loop.node.calls) == 1


def test_timeout_formed_qc_is_applied_locally_before_rebroadcast() -> None:
    ex = _TimeoutExecutorQcApply()
    loop = _mk_loop(ex)
    loop._on_bft_timeout("peer-a", _timeout_msg())
    assert len(ex.applied_qcs) == 1
    assert ex.applied_qcs[0]["block_id"] == "b6"
    assert len(loop.node.calls) == 1


def test_vote_formed_qc_apply_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_VoteExecutorQcApplyBoom())
    with pytest.raises(BftInboundProcessingError, match="vote_local_qc_apply_failed"):
        loop._on_bft_vote("peer-a", _vote_msg())


def test_timeout_formed_qc_apply_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_TimeoutExecutorQcApplyBoom())
    with pytest.raises(BftInboundProcessingError, match="timeout_local_qc_apply_failed"):
        loop._on_bft_timeout("peer-a", _timeout_msg())
