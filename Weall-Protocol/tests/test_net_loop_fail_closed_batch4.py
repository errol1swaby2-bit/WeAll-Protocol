from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.messages import BftProposalMsg, BftQcMsg, BftTimeoutMsg, BftVoteMsg, MsgType, WireHeader
from weall.net.net_loop import BftInboundProcessingError, NetLoopConfig, NetMeshLoop


class _FakeNode:
    def __init__(self, *, fail_broadcast: bool = False) -> None:
        self.cfg = SimpleNamespace(peer_id="local-peer", chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef")
        self.calls = []
        self._fail_broadcast = bool(fail_broadcast)

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        if self._fail_broadcast:
            raise RuntimeError("broadcast boom")
        self.calls.append((msg, exclude_peer_id))
        return 1


class _FakeMempool:
    def read_all(self):
        return []


class _ProposalExecutorBoom:
    def bft_on_proposal(self, proposal):
        raise ValueError("proposal executor boom")


class _VoteExecutorBoom:
    def bft_on_vote(self, vote):
        raise ValueError("vote executor boom")


class _QcExecutorBoom:
    def bft_on_qc(self, qc):
        raise ValueError("qc executor boom")


class _TimeoutExecutorBoom:
    def bft_on_timeout(self, timeout):
        raise ValueError("timeout executor boom")


class _ProposalExecutorVote:
    def bft_on_proposal(self, proposal):
        return {
            "chain_id": "chain-A",
            "view": int(proposal.get("view") or 0),
            "block_id": str((proposal.get("block") or {}).get("block_id") or ""),
            "parent_id": str((proposal.get("block") or {}).get("prev_block_id") or ""),
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
        }


class _VoteExecutorQc:
    def bft_on_vote(self, vote):
        return {
            "chain_id": "chain-A",
            "view": int(vote.get("view") or 0),
            "block_id": str(vote.get("block_id") or ""),
            "parent_id": str(vote.get("parent_id") or ""),
            "votes": [vote],
        }



def _mk_loop(executor, *, fail_broadcast: bool = False) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=_FakeMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode(fail_broadcast=fail_broadcast)
    loop._bft_enabled = True
    return loop



def _proposal_msg() -> BftProposalMsg:
    return BftProposalMsg(
        header=WireHeader(type=MsgType.BFT_PROPOSAL, chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef"),
        view=7,
        proposer="peer-a",
        block={
            "block_id": "b7",
            "height": 7,
            "view": 7,
            "prev_block_id": "b6",
            "header": {
                "chain_id": "chain-A",
                "height": 7,
                "prev_block_hash": "00" * 32,
                "block_ts_ms": 1700000000007,
                "tx_ids": [],
                "receipts_root": "11" * 32,
                "state_root": "22" * 32,
            },
        },
        justify_qc=None,
    )



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



def _qc_msg() -> BftQcMsg:
    return BftQcMsg(
        header=WireHeader(type=MsgType.BFT_QC, chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef"),
        qc={
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "parent_id": "b6",
            "votes": [{"signer": "@v1"}],
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



def test_on_bft_proposal_prod_fails_closed_on_executor_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_ProposalExecutorBoom())
    with pytest.raises(BftInboundProcessingError, match="proposal_executor_failed"):
        loop._on_bft_proposal("peer-a", _proposal_msg())



def test_on_bft_vote_prod_fails_closed_on_executor_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_VoteExecutorBoom())
    with pytest.raises(BftInboundProcessingError, match="vote_executor_failed"):
        loop._on_bft_vote("peer-a", _vote_msg())



def test_on_bft_qc_prod_fails_closed_on_executor_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_QcExecutorBoom())
    with pytest.raises(BftInboundProcessingError, match="qc_executor_failed"):
        loop._on_bft_qc("peer-a", _qc_msg())



def test_on_bft_timeout_prod_fails_closed_on_executor_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_TimeoutExecutorBoom())
    with pytest.raises(BftInboundProcessingError, match="timeout_executor_failed"):
        loop._on_bft_timeout("peer-a", _timeout_msg())



def test_on_bft_vote_prod_fails_closed_on_qc_broadcast_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_VoteExecutorQc(), fail_broadcast=True)
    with pytest.raises(BftInboundProcessingError, match="vote_qc_broadcast_failed"):
        loop._on_bft_vote("peer-a", _vote_msg())



def test_on_bft_timeout_prod_fails_closed_on_timeout_broadcast_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_TimeoutExecutorBoom(), fail_broadcast=True)
    # executor failure fires first; use object without timeout hook to hit broadcast path
    loop = _mk_loop(object(), fail_broadcast=True)
    with pytest.raises(BftInboundProcessingError, match="timeout_broadcast_failed"):
        loop._on_bft_timeout("peer-a", _timeout_msg())
