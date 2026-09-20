from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from weall.net.messages import (
    BftTimeoutMsg,
    BftVoteMsg,
    MsgType,
    WireHeader,
)
from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _Mempool:
    def read_all(self):
        return []

    def peek(self, _n: int):
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


class _InboundBranchExecutor:
    chain_id = "chain-A"
    tx_index = None

    def __init__(self) -> None:
        self.generation = 0
        self.current = True
        self.guard_calls: list[str] = []
        self.timeout_calls = 0

    def read_state(self) -> dict[str, Any]:
        return {}

    def snapshot(self) -> dict[str, Any]:
        return {}

    def tx_index_hash(self) -> str:
        return "deadbeef"

    def _schema_version(self) -> str:
        return "1"

    def bft_branch_generation(self) -> int:
        return int(self.generation)

    def bft_artifact_dedupe_key(self, kind: str, payload: dict) -> str:
        return f"{kind}:{payload.get('view')}:{payload.get('signer') or payload.get('block_id')}"

    def bft_artifact_was_accepted(self, kind: str, payload: dict) -> bool:
        del kind, payload
        return bool(self.current)

    def bft_on_timeout(self, payload: dict) -> int:
        del payload
        self.timeout_calls += 1
        return 8

    def bft_timeout_was_accepted(self, payload: dict) -> bool:
        del payload
        # Report branch-A admission, then simulate destructive branch replacement
        # before the network layer performs its post-authentication side effect.
        self.current = False
        self.generation += 1
        return True

    def bft_run_postauth_side_effect_if_current(
        self,
        kind: str,
        payload: dict,
        side_effect,
    ) -> bool:
        del payload
        self.guard_calls.append(str(kind))
        if not self.current:
            return False
        side_effect()
        return True


def _loop(executor: _InboundBranchExecutor) -> NetMeshLoop:
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
    loop._relay_cfg = lambda: object()  # type: ignore[method-assign]
    return loop


def _header(t: MsgType) -> WireHeader:
    return WireHeader(
        type=t,
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="deadbeef",
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


def _vote() -> BftVoteMsg:
    return BftVoteMsg(
        header=_header(MsgType.BFT_VOTE),
        view=7,
        vote={
            "t": "VOTE",
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "block_hash": "77" * 32,
            "parent_id": "b6",
            "signer": "@v1",
            "pubkey": "pub",
            "sig": "sig",
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
        },
    )


def test_inbound_timeout_is_not_regossiped_after_branch_reset_post_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _InboundBranchExecutor()
    loop = _loop(ex)

    monkeypatch.setattr(loop, "_bft_payload_reject_reason", lambda *_a, **_k: None)
    monkeypatch.setattr(loop, "_bft_prefilter_reject_reason", lambda *_a, **_k: (None, {}))
    monkeypatch.setattr("weall.net.net_loop._cheap_validate_bft_payload", lambda *_a, **_k: None)

    assert loop._on_bft_timeout("peer-a", _timeout()) is not True

    assert ex.timeout_calls == 1
    assert loop.node.calls == []
    assert loop._bft_timeout_seen == {}
    assert ex.guard_calls == ["timeout"]


def test_bft_relay_acceptance_is_not_recorded_after_branch_reset_post_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _InboundBranchExecutor()
    loop = _loop(ex)
    msg = _vote()

    monkeypatch.setattr(
        "weall.net.net_loop.validate_relay_envelope",
        lambda envelope, *, cfg: dict(envelope),
    )
    monkeypatch.setattr("weall.net.net_loop.decode_relay_payload", lambda _env: msg)

    def _accepted_then_reset(_peer_id: str, _msg: object) -> bool:
        ex.current = False
        ex.generation += 1
        return True

    monkeypatch.setattr(loop, "_on_bft_vote", _accepted_then_reset)

    env = {"relay_id": "rid-postauth-reset", "sender_peer_id": "relay-peer"}

    assert loop._relay_process_envelope(env) is False
    assert env["relay_id"] not in loop._relay_seen
    assert ex.guard_calls == ["vote"]


def test_bft_relay_ack_is_not_sent_if_branch_resets_after_process_before_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _InboundBranchExecutor()
    loop = _loop(ex)
    loop._relay_client_enabled = True
    loop._relay_urls = ["http://relay.example"]
    loop._relay_poll_ms = 1
    loop._relay_last_poll_ms = 0

    msg = _vote()
    env = {"relay_id": "rid-ack-race", "sender_peer_id": "relay-peer"}
    acks: list[list[str]] = []

    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: 10_000)
    monkeypatch.setattr(
        loop,
        "_relay_fetch",
        lambda _base, _peer_id: {"ok": True, "messages": [env]},
    )
    monkeypatch.setattr(loop, "_relay_ack", lambda _base, _peer_id, ids: acks.append(list(ids)))
    monkeypatch.setattr(
        "weall.net.net_loop.validate_relay_envelope",
        lambda envelope, *, cfg: dict(envelope),
    )
    monkeypatch.setattr("weall.net.net_loop.decode_relay_payload", lambda _env: msg)
    monkeypatch.setattr(loop, "_on_bft_vote", lambda _peer_id, _msg: True)

    original_process = loop._relay_process_envelope

    def _process_then_reset(envelope: dict) -> bool:
        out = original_process(envelope)
        if out:
            ex.current = False
            ex.generation += 1
        return out

    monkeypatch.setattr(loop, "_relay_process_envelope", _process_then_reset)

    loop._relay_poll_tick()

    assert acks == []
