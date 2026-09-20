from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from weall.net.messages import BftQcMsg, BftTimeoutMsg, BftVoteMsg, MsgType, WireHeader
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


def _semantic_key(kind: str, payload: dict) -> str:
    kind = str(kind)
    if kind == "vote":
        projected = {
            "t": "VOTE",
            "chain_id": str(payload.get("chain_id") or "chain-A"),
            "view": int(payload.get("view") or 0),
            "block_id": str(payload.get("block_id") or ""),
            "block_hash": str(payload.get("block_hash") or ""),
            "parent_id": str(payload.get("parent_id") or ""),
            "signer": str(payload.get("signer") or ""),
            "sig_profile": str(payload.get("sig_profile") or "pq-mldsa-v1"),
            "validator_epoch": int(payload.get("validator_epoch") or 0),
            "validator_set_hash": str(payload.get("validator_set_hash") or ""),
            "consensus_phase": str(payload.get("consensus_phase") or "bft_active"),
        }
    elif kind == "timeout":
        projected = {
            "t": "TIMEOUT",
            "chain_id": str(payload.get("chain_id") or "chain-A"),
            "view": int(payload.get("view") or 0),
            "high_qc_id": str(payload.get("high_qc_id") or ""),
            "signer": str(payload.get("signer") or ""),
            "sig_profile": str(payload.get("sig_profile") or "pq-mldsa-v1"),
            "validator_epoch": int(payload.get("validator_epoch") or 0),
            "validator_set_hash": str(payload.get("validator_set_hash") or ""),
            "consensus_phase": str(payload.get("consensus_phase") or "bft_active"),
        }
    elif kind == "qc":
        projected = {
            "t": "QC",
            "chain_id": str(payload.get("chain_id") or "chain-A"),
            "view": int(payload.get("view") or 0),
            "block_id": str(payload.get("block_id") or ""),
            "block_hash": str(payload.get("block_hash") or ""),
            "parent_id": str(payload.get("parent_id") or ""),
            "validator_epoch": int(payload.get("validator_epoch") or 0),
            "validator_set_hash": str(payload.get("validator_set_hash") or ""),
            "consensus_phase": str(payload.get("consensus_phase") or "bft_active"),
        }
    else:
        return ""
    raw = json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class _Executor:
    def __init__(self) -> None:
        self.vote_calls = 0
        self.qc_calls = 0
        self.timeout_calls = 0
        self.timeout_ready = True

    def bft_artifact_dedupe_key(self, kind: str, payload: dict) -> str:
        return _semantic_key(kind, payload)

    def bft_artifact_was_accepted(self, kind: str, payload: dict) -> bool:
        return kind in {"vote", "qc"}

    def bft_on_vote(self, payload: dict):
        self.vote_calls += 1
        return None

    def bft_on_qc(self, payload: dict):
        self.qc_calls += 1
        return None

    def bft_on_timeout(self, payload: dict):
        self.timeout_calls += 1
        return None

    def bft_timeout_was_accepted(self, payload: dict) -> bool:
        return bool(self.timeout_ready)

    def bft_current_view(self) -> int:
        return 7

    def bft_current_validator_epoch(self) -> int:
        return 2


def _loop(executor: _Executor) -> NetMeshLoop:
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


def _vote(*, sig: str, noise: str) -> BftVoteMsg:
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
            "sig": sig,
            "sig_profile": "pq-mldsa-v1",
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
            "transport_noise": noise,
        },
    )


def _qc(*, proof: str, noise: str) -> BftQcMsg:
    return BftQcMsg(
        header=_header(MsgType.BFT_QC),
        qc={
            "t": "QC",
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "block_hash": "hash-b7",
            "parent_id": "b6",
            "votes": [{"signer": "@v1", "sig": proof}],
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
            "transport_noise": noise,
        },
    )


def _timeout(*, sig: str, noise: str) -> BftTimeoutMsg:
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
            "sig": sig,
            "sig_profile": "pq-mldsa-v1",
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
            "transport_noise": noise,
        },
    )


def test_postauth_vote_wire_aliases_share_one_network_identity() -> None:
    ex = _Executor()
    loop = _loop(ex)

    assert loop._on_bft_vote("peer-a", _vote(sig="sig-a", noise="a")) is True
    assert loop._on_bft_vote("peer-b", _vote(sig="sig-b", noise="b")) is True
    assert loop._on_bft_vote("peer-c", _vote(sig="sig-c", noise="c")) is True

    assert ex.vote_calls == 1
    assert len(loop._bft_msg_seen) == 1


def test_postauth_qc_proof_aliases_share_one_network_identity() -> None:
    ex = _Executor()
    loop = _loop(ex)

    assert loop._on_bft_qc("peer-a", _qc(proof="proof-a", noise="a")) is True
    assert loop._on_bft_qc("peer-b", _qc(proof="proof-b", noise="b")) is True
    assert loop._on_bft_qc("peer-c", _qc(proof="proof-c", noise="c")) is True

    assert ex.qc_calls == 1
    assert len(loop._bft_msg_seen) == 1


def test_postauth_timeout_aliases_are_not_reverified_or_regossiped() -> None:
    ex = _Executor()
    loop = _loop(ex)

    first = _timeout(sig="sig-a", noise="a")
    alias_one = _timeout(sig="sig-b", noise="b")
    alias_two = _timeout(sig="sig-c", noise="c")

    assert loop._on_bft_timeout("peer-a", first) is True
    assert loop._on_bft_timeout("peer-b", alias_one) is True
    assert loop._on_bft_timeout("peer-c", alias_two) is True

    assert ex.timeout_calls == 1
    assert len(loop.node.calls) == 1
    assert loop.node.calls[0] == (first, "peer-a")
    assert len(loop._bft_timeout_seen) == 1


def test_rejected_semantic_timeout_does_not_poison_later_valid_alias() -> None:
    ex = _Executor()
    ex.timeout_ready = False
    loop = _loop(ex)

    assert loop._on_bft_timeout("peer-a", _timeout(sig="bad", noise="rejected")) is None
    assert ex.timeout_calls == 1
    assert loop.node.calls == []
    assert loop._bft_timeout_seen == {}

    ex.timeout_ready = True
    accepted = _timeout(sig="good", noise="accepted")
    assert loop._on_bft_timeout("peer-b", accepted) is True
    assert ex.timeout_calls == 2
    assert loop.node.calls == [(accepted, "peer-b")]
    assert len(loop._bft_timeout_seen) == 1


def test_locally_broadcast_vote_is_preseeded_in_semantic_seen_cache() -> None:
    ex = _Executor()
    loop = _loop(ex)

    local_vote = _vote(sig="sig-local", noise="local")
    loop._broadcast_bft_vote(local_vote.vote)

    assert len(loop.node.calls) == 1
    assert len(loop._bft_msg_seen) == 1

    alias = _vote(sig="sig-echo", noise="echo")
    assert loop._on_bft_vote("peer-echo", alias) is True
    assert ex.vote_calls == 0
    assert len(loop.node.calls) == 1


def test_locally_broadcast_timeout_is_not_regossiped_when_echoed() -> None:
    ex = _Executor()
    loop = _loop(ex)

    local_timeout = _timeout(sig="sig-local", noise="local")
    loop._broadcast_bft_timeout(local_timeout.timeout)

    assert len(loop.node.calls) == 1
    assert len(loop._bft_timeout_seen) == 1

    alias = _timeout(sig="sig-echo", noise="echo")
    assert loop._on_bft_timeout("peer-echo", alias) is True
    assert ex.timeout_calls == 0
    assert len(loop.node.calls) == 1
