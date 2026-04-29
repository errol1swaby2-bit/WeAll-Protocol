from __future__ import annotations

from types import SimpleNamespace

from weall.net.messages import BftProposalMsg, BftTimeoutMsg, BftVoteMsg, MsgType, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime import metrics as metrics_mod


class _Exec:
    chain_id = "chain-A"

    def __init__(self) -> None:
        self.proposals: list[dict] = []
        self.votes: list[dict] = []
        self.timeouts: list[dict] = []
        self.events: list[dict] = []

    def snapshot(self):
        return {"height": 0}

    def tx_index_hash(self):
        return "deadbeef"

    def _schema_version(self):
        return "1"

    def bft_current_view(self) -> int:
        return 10

    def bft_current_validator_epoch(self) -> int:
        return 7

    def bft_on_proposal(self, proposal: dict):
        self.proposals.append(dict(proposal))
        return None

    def bft_on_vote(self, vote: dict):
        self.votes.append(dict(vote))
        return None

    def bft_on_timeout(self, timeout: dict):
        self.timeouts.append(dict(timeout))
        return None

    def _bft_record_event(self, event: str, **payload) -> None:
        self.events.append({"event": event, **payload})


class _Mempool:
    pass


class _Node:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
            peer_id="n1",
        )
        self.broadcasts = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> None:
        self.broadcasts.append((msg, exclude_peer_id))


def _reset_metrics() -> None:
    metrics_mod._counters.clear()
    metrics_mod._gauges.clear()


def _loop() -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=_Exec(),
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
    return loop


def _proposal_msg(*, view: int, validator_epoch: int) -> BftProposalMsg:
    return BftProposalMsg(
        header=WireHeader(
            type=MsgType.BFT_PROPOSAL,
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        ),
        view=view,
        proposer="@v1",
        block={
            "block_id": f"b-{view}",
            "block_hash": f"hash-{view}",
            "height": view,
            "view": view,
            "prev_block_id": f"b-{view - 1}",
            "validator_epoch": validator_epoch,
            "validator_set_hash": "set-7",
        },
        justify_qc=None,
    )


def _vote_msg(*, view: int, validator_epoch: int) -> BftVoteMsg:
    return BftVoteMsg(
        header=WireHeader(
            type=MsgType.BFT_VOTE,
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        ),
        view=view,
        vote={
            "t": "VOTE",
            "chain_id": "chain-A",
            "view": view,
            "block_id": f"b-{view}",
            "block_hash": f"hash-{view}",
            "parent_id": f"b-{view - 1}",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
            "validator_epoch": validator_epoch,
            "validator_set_hash": "set-7",
        },
    )


def _timeout_msg(*, view: int, validator_epoch: int) -> BftTimeoutMsg:
    return BftTimeoutMsg(
        header=WireHeader(
            type=MsgType.BFT_TIMEOUT,
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        ),
        view=view,
        timeout={
            "t": "TIMEOUT",
            "chain_id": "chain-A",
            "view": view,
            "high_qc_id": f"b-{max(1, view - 1)}",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
            "validator_epoch": validator_epoch,
            "validator_set_hash": "set-7",
        },
    )


def test_stale_proposal_view_is_prefiltered_before_executor_batch109() -> None:
    _reset_metrics()
    loop = _loop()

    loop._on_bft_proposal("peer-a", _proposal_msg(view=7, validator_epoch=7))

    assert loop._executor.proposals == []
    assert loop._executor.events[-1]["reason"] == "stale_view"
    assert loop._executor.events[-1]["summary"]["local_view"] == 10
    snap = metrics_mod.snapshot()
    assert int(snap["counters"].get("net_bft_proposal_rejected", 0)) >= 1
    assert int(snap["counters"].get("net_bft_proposal_reject_stale_view", 0)) >= 1


def test_stale_vote_epoch_is_prefiltered_before_executor_batch109() -> None:
    _reset_metrics()
    loop = _loop()

    loop._on_bft_vote("peer-a", _vote_msg(view=10, validator_epoch=6))

    assert loop._executor.votes == []
    assert loop._executor.events[-1]["reason"] == "stale_epoch"
    assert loop._executor.events[-1]["summary"]["local_validator_epoch"] == 7
    snap = metrics_mod.snapshot()
    assert int(snap["counters"].get("net_bft_vote_rejected", 0)) >= 1
    assert int(snap["counters"].get("net_bft_vote_reject_stale_epoch", 0)) >= 1


def test_stale_timeout_view_is_prefiltered_before_executor_batch109() -> None:
    _reset_metrics()
    loop = _loop()

    loop._on_bft_timeout("peer-a", _timeout_msg(view=8, validator_epoch=7))

    assert loop._executor.timeouts == []
    assert loop._executor.events[-1]["reason"] == "stale_view"
    snap = metrics_mod.snapshot()
    assert int(snap["counters"].get("net_bft_timeout_rejected", 0)) >= 1
    assert int(snap["counters"].get("net_bft_timeout_reject_stale_view", 0)) >= 1
