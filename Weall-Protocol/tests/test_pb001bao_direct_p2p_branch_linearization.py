from __future__ import annotations

from types import SimpleNamespace

import pytest

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


class _RaceExecutor:
    def __init__(self) -> None:
        self.generation = 0
        self.current = {"proposal", "vote", "qc", "timeout"}
        self.calls = {"proposal": 0, "vote": 0, "qc": 0, "timeout": 0}

    def bft_branch_generation(self) -> int:
        return int(self.generation)

    def checkpoint_reset(self) -> None:
        self.generation += 1
        self.current.clear()

    def bft_artifact_dedupe_key(self, kind: str, payload: dict) -> str:
        return f"{kind}:{payload.get('view')}:{payload.get('signer') or payload.get('block_id')}"

    def bft_artifact_was_accepted(self, kind: str, payload: dict) -> bool:
        del payload
        return str(kind) in self.current

    def bft_on_proposal(self, payload: dict):
        del payload
        self.calls["proposal"] += 1
        return None

    def bft_on_vote(self, payload: dict):
        del payload
        self.calls["vote"] += 1
        return None

    def bft_on_qc(self, payload: dict):
        del payload
        self.calls["qc"] += 1
        return None

    def bft_on_timeout(self, payload: dict):
        del payload
        self.calls["timeout"] += 1
        return None

    def bft_timeout_was_accepted(self, payload: dict) -> bool:
        del payload
        return "timeout" in self.current


def _loop(executor: _RaceExecutor) -> NetMeshLoop:
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
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
        },
    )


def _qc() -> BftQcMsg:
    return BftQcMsg(
        header=_header(MsgType.BFT_QC),
        qc={
            "t": "QC",
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "block_hash": "hash-b7",
            "parent_id": "b6",
            "votes": [{"signer": "@v1", "sig": "proof"}],
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
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
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
        },
    )


def _bypass_prefilters(loop: NetMeshLoop, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loop, "_bft_payload_reject_reason", lambda *_a, **_k: None)
    monkeypatch.setattr(loop, "_bft_prefilter_reject_reason", lambda *_a, **_k: (None, {}))
    monkeypatch.setattr("weall.net.net_loop._cheap_validate_bft_payload", lambda *_a, **_k: None)


def _inject_reset_between_sync_and_seen(
    loop: NetMeshLoop,
    executor: _RaceExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = loop._seen_contains
    fired = {"value": False}

    def _seen_after_reset(*args, **kwargs):
        if not fired["value"]:
            fired["value"] = True
            executor.checkpoint_reset()
        return original(*args, **kwargs)

    monkeypatch.setattr(loop, "_seen_contains", _seen_after_reset)


def test_stale_proposal_seen_hit_reaches_branch_b_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _RaceExecutor()
    loop = _loop(ex)
    msg = _proposal()
    _bypass_prefilters(loop, monkeypatch)

    proposal = loop._mk_bft_proposal_json(msg)
    key = loop._bft_generic_key({"t": "proposal", "v": proposal})
    loop._bft_msg_seen[key] = 10_000
    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: 10_001)
    _inject_reset_between_sync_and_seen(loop, ex, monkeypatch)

    assert loop._on_bft_proposal("peer-b", msg) is False
    assert ex.calls["proposal"] == 1


def test_stale_vote_seen_hit_reaches_branch_b_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _RaceExecutor()
    loop = _loop(ex)
    msg = _vote()
    _bypass_prefilters(loop, monkeypatch)

    vote = loop._mk_bft_vote_json(msg)
    key = loop._bft_network_dedupe_key("vote", vote)
    loop._bft_msg_seen[key] = 10_000
    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: 10_001)
    _inject_reset_between_sync_and_seen(loop, ex, monkeypatch)

    assert loop._on_bft_vote("peer-b", msg) is False
    assert ex.calls["vote"] == 1


def test_stale_qc_seen_hit_reaches_branch_b_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _RaceExecutor()
    loop = _loop(ex)
    msg = _qc()
    _bypass_prefilters(loop, monkeypatch)

    qc = dict(msg.qc)
    key = loop._bft_network_dedupe_key("qc", qc)
    loop._bft_msg_seen[key] = 10_000
    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: 10_001)
    _inject_reset_between_sync_and_seen(loop, ex, monkeypatch)

    assert loop._on_bft_qc("peer-b", msg) is False
    assert ex.calls["qc"] == 1


def test_stale_timeout_seen_hit_reaches_branch_b_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _RaceExecutor()
    loop = _loop(ex)
    msg = _timeout()
    _bypass_prefilters(loop, monkeypatch)

    key = loop._bft_timeout_key(msg)
    loop._bft_timeout_seen[key] = 10_000
    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: 10_001)
    _inject_reset_between_sync_and_seen(loop, ex, monkeypatch)

    assert loop._on_bft_timeout("peer-b", msg) is None
    assert ex.calls["timeout"] == 1
