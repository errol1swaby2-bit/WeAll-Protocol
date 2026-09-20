from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from weall.net.messages import BftTimeoutMsg, BftVoteMsg, MsgType, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime.executor import WeAllExecutor


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
    projected = {
        "kind": str(kind),
        "chain_id": str(payload.get("chain_id") or "chain-A"),
        "view": int(payload.get("view") or 0),
        "block_id": str(payload.get("block_id") or ""),
        "block_hash": str(payload.get("block_hash") or ""),
        "high_qc_id": str(payload.get("high_qc_id") or ""),
        "signer": str(payload.get("signer") or ""),
    }
    raw = json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class _BranchAwareExecutor:
    def __init__(self) -> None:
        self.generation = 0
        self.ready = True
        self.accepted: set[str] = set()
        self.vote_calls = 0
        self.timeout_calls = 0

    def bft_branch_generation(self) -> int:
        return int(self.generation)

    def checkpoint_reset(self) -> None:
        self.generation += 1
        self.accepted.clear()

    def bft_artifact_dedupe_key(self, kind: str, payload: dict) -> str:
        return _semantic_key(kind, payload)

    def bft_artifact_was_accepted(self, kind: str, payload: dict) -> bool:
        del payload
        return str(kind) in self.accepted

    def bft_on_vote(self, payload: dict):
        del payload
        self.vote_calls += 1
        if self.ready:
            self.accepted.add("vote")
        return None

    def bft_on_timeout(self, payload: dict):
        del payload
        self.timeout_calls += 1
        if self.ready:
            self.accepted.add("timeout")
        return None

    def bft_timeout_was_accepted(self, payload: dict) -> bool:
        del payload
        return "timeout" in self.accepted

    def bft_current_view(self) -> int:
        return 7

    def bft_current_validator_epoch(self) -> int:
        return 2


def _loop(executor: _BranchAwareExecutor) -> NetMeshLoop:
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
    loop._relay_seen_ttl_ms = 999_999
    loop._relay_cfg = lambda: object()  # type: ignore[method-assign]
    return loop


def _header(kind: MsgType) -> WireHeader:
    return WireHeader(
        type=kind,
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="deadbeef",
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
            "sig_profile": "pq-mldsa-v1",
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
            "sig_profile": "pq-mldsa-v1",
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
        },
    )


def test_vote_seen_cache_does_not_cross_destructive_branch_reset() -> None:
    ex = _BranchAwareExecutor()
    loop = _loop(ex)
    msg = _vote()

    assert loop._on_bft_vote("peer-a", msg) is True
    assert ex.vote_calls == 1
    assert len(loop._bft_msg_seen) == 1

    ex.checkpoint_reset()
    ex.ready = False

    assert loop._on_bft_vote("peer-b", msg) is False
    assert ex.vote_calls == 2
    assert loop._bft_msg_seen == {}


def test_timeout_seen_cache_does_not_cross_destructive_branch_reset() -> None:
    ex = _BranchAwareExecutor()
    loop = _loop(ex)
    msg = _timeout()

    assert loop._on_bft_timeout("peer-a", msg) is True
    assert ex.timeout_calls == 1
    assert len(loop.node.calls) == 1
    assert len(loop._bft_timeout_seen) == 1

    ex.checkpoint_reset()
    ex.ready = False

    assert loop._on_bft_timeout("peer-b", msg) is None
    assert ex.timeout_calls == 2
    assert len(loop.node.calls) == 1
    assert loop._bft_timeout_seen == {}


def test_bft_relay_seen_truth_is_invalidated_by_destructive_branch_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _BranchAwareExecutor()
    loop = _loop(ex)
    message = _vote()
    calls: list[str] = []

    monkeypatch.setattr(
        "weall.net.net_loop.validate_relay_envelope",
        lambda envelope, *, cfg: dict(envelope),
    )
    monkeypatch.setattr("weall.net.net_loop.decode_relay_payload", lambda _env: message)
    monkeypatch.setattr(
        loop,
        "_on_bft_vote",
        lambda _peer_id, _msg: calls.append("vote") or True,
    )

    env = {"relay_id": "rid-branch", "sender_peer_id": "relay-peer"}
    assert loop._relay_process_envelope(env) is True
    assert calls == ["vote"]
    assert env["relay_id"] in loop._relay_seen

    ex.checkpoint_reset()

    assert loop._relay_process_envelope(env) is True
    assert calls == ["vote", "vote"]


def test_executor_exposes_monotonic_process_local_bft_branch_generation() -> None:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex._bft_branch_generation = 4

    assert ex.bft_branch_generation() == 4

    ex._clear_in_memory_bft_branch_state()

    assert ex.bft_branch_generation() == 5
