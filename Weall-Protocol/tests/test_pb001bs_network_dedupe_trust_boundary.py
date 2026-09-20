from __future__ import annotations

from types import SimpleNamespace

from weall.net.messages import (
    BftProposalMsg,
    BftQcMsg,
    BftTimeoutMsg,
    BftVoteMsg,
    MsgType,
    WireHeader,
)
from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _Mempool:
    def read_all(self):
        return []


class _Node:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            peer_id="local",
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        )
        self.calls: list[tuple[object, str]] = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


def _loop(executor) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    loop.node = _Node()
    loop._bft_enabled = True
    loop._bft_msg_seen_ttl_ms = 999_999
    loop._bft_timeout_seen_ttl_ms = 999_999
    return loop


def _header(kind: MsgType) -> WireHeader:
    return WireHeader(
        type=kind,
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="deadbeef",
    )


def _proposal_msg() -> BftProposalMsg:
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


def _vote_msg() -> BftVoteMsg:
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


def _qc_msg() -> BftQcMsg:
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


def _timeout_msg() -> BftTimeoutMsg:
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


class _ProposalRetryExecutor:
    def __init__(self) -> None:
        self.ready = False
        self.calls = 0

    def bft_on_proposal(self, proposal: dict):
        self.calls += 1
        if not self.ready:
            return None
        return {
            "t": "VOTE",
            "chain_id": "chain-A",
            "view": int(proposal.get("view") or 0),
            "block_id": str((proposal.get("block") or {}).get("block_id") or ""),
            "block_hash": "hash-b7",
            "parent_id": "b6",
            "signer": "@local",
            "pubkey": "pub",
            "sig": "sig",
        }


class _VoteRetryExecutor:
    def __init__(self) -> None:
        self.ready = False
        self.calls = 0
        self.applied_qcs = 0

    def bft_on_vote(self, vote: dict):
        self.calls += 1
        if not self.ready:
            return None
        return {
            "chain_id": "chain-A",
            "view": int(vote.get("view") or 0),
            "block_id": str(vote.get("block_id") or ""),
            "block_hash": str(vote.get("block_hash") or ""),
            "parent_id": str(vote.get("parent_id") or ""),
            "votes": [dict(vote)],
        }

    def bft_on_qc(self, qc: dict):
        self.applied_qcs += 1
        return {"accepted": True}


class _QcRetryExecutor:
    def __init__(self) -> None:
        self.ready = False
        self.calls = 0

    def bft_on_qc(self, qc: dict):
        self.calls += 1
        if not self.ready:
            return None
        return {"accepted": True}


class _TimeoutRetryExecutor:
    def __init__(self) -> None:
        self.ready = False
        self.calls = 0
        self.accepted = False

    def bft_on_timeout(self, timeout: dict):
        self.calls += 1
        self.accepted = bool(self.ready)
        return {} if self.accepted else None

    def bft_timeout_was_accepted(self, timeout: dict) -> bool:
        return bool(self.accepted)


class _RejectTimeoutExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def bft_on_timeout(self, timeout: dict):
        self.calls += 1
        return None

    def bft_timeout_was_accepted(self, timeout: dict) -> bool:
        return False


def test_executor_rejected_proposal_retry_is_not_network_poisoned() -> None:
    ex = _ProposalRetryExecutor()
    loop = _loop(ex)
    msg = _proposal_msg()

    loop._on_bft_proposal("peer-a", msg)
    assert ex.calls == 1

    ex.ready = True
    loop._on_bft_proposal("peer-b", msg)

    assert ex.calls == 2
    assert len(loop.node.calls) == 1


def test_executor_rejected_vote_retry_is_not_network_poisoned() -> None:
    ex = _VoteRetryExecutor()
    loop = _loop(ex)
    msg = _vote_msg()

    loop._on_bft_vote("peer-a", msg)
    assert ex.calls == 1

    ex.ready = True
    loop._on_bft_vote("peer-b", msg)

    assert ex.calls == 2
    assert ex.applied_qcs == 1
    assert len(loop.node.calls) == 1


def test_executor_rejected_qc_retry_is_not_network_poisoned() -> None:
    ex = _QcRetryExecutor()
    loop = _loop(ex)
    msg = _qc_msg()

    loop._on_bft_qc("peer-a", msg)
    assert ex.calls == 1

    ex.ready = True
    loop._on_bft_qc("peer-b", msg)

    assert ex.calls == 2


def test_rejected_timeout_retry_remains_eligible_and_only_accepted_copy_relays() -> None:
    ex = _TimeoutRetryExecutor()
    loop = _loop(ex)
    msg = _timeout_msg()

    loop._on_bft_timeout("peer-a", msg)
    assert ex.calls == 1
    assert loop.node.calls == []

    ex.ready = True
    loop._on_bft_timeout("peer-b", msg)

    assert ex.calls == 2
    assert len(loop.node.calls) == 1
    relayed, excluded = loop.node.calls[0]
    assert relayed == msg
    assert excluded == "peer-b"


def test_rejected_timeout_is_never_rebroadcast() -> None:
    ex = _RejectTimeoutExecutor()
    loop = _loop(ex)

    loop._on_bft_timeout("peer-a", _timeout_msg())

    assert ex.calls == 1
    assert loop.node.calls == []
