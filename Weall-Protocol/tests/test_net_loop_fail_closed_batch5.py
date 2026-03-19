from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.net_loop import BftOutboundBridgeError, NetLoopConfig, NetMeshLoop


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


class _ExecutorSentMarkBoom:
    def bft_pending_outbound_messages(self):
        return [{"kind": "vote", "payload": {"view": 7, "block_id": "b7", "parent_id": "b6"}}]

    def bft_mark_outbound_sent(self, kind: str, payload) -> None:
        raise ValueError("sent mark boom")


class _ExecutorLeaderProposal:
    def bft_leader_propose(self):
        return {"block_id": "b7", "view": 7, "prev_block_id": "b6"}


class _ExecutorLeaderBoom:
    def bft_leader_propose(self):
        raise ValueError("leader boom")


class _ExecutorDriveTimeoutsBoom:
    def bft_drive_timeouts(self, now_ms: int):
        raise ValueError("drive boom")


class _ExecutorTimeoutCheckBoom:
    def bft_timeout_check(self):
        raise ValueError("timeout check boom")


class _ExecutorDriveOutputs:
    def bft_drive_timeouts(self, now_ms: int):
        return {
            "vote": {"view": 7, "block_id": "b7", "parent_id": "b6"},
            "timeout": {"view": 7, "high_qc_id": "b6", "signer": "@v1"},
        }


def _mk_loop(executor, *, fail_broadcast: bool = False) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=_FakeMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode(fail_broadcast=fail_broadcast)
    loop._bft_enabled = True
    loop._bft_propose_interval_ms = 1
    loop._bft_vote_interval_ms = 1
    loop._bft_timeout_interval_ms = 1
    loop._last_bft_propose_ms = 0
    loop._last_bft_vote_ms = 0
    loop._last_bft_timeout_ms = 0
    return loop


def test_outbound_bft_tick_prod_fails_closed_on_sent_mark_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_ExecutorSentMarkBoom())
    with pytest.raises(BftOutboundBridgeError, match="mark_outbound_sent_failed:vote"):
        loop._outbound_bft_tick()


def test_outbound_bft_tick_prod_fails_closed_on_proposal_broadcast_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_ExecutorLeaderProposal(), fail_broadcast=True)
    with pytest.raises(BftOutboundBridgeError, match="proposal_broadcast_failed"):
        loop._outbound_bft_tick()


def test_outbound_bft_tick_prod_fails_closed_on_leader_propose_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_ExecutorLeaderBoom())
    with pytest.raises(BftOutboundBridgeError, match="leader_propose_failed"):
        loop._outbound_bft_tick()


def test_outbound_bft_tick_prod_fails_closed_on_drive_timeouts_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_ExecutorDriveTimeoutsBoom())
    with pytest.raises(BftOutboundBridgeError, match="drive_timeouts_failed"):
        loop._outbound_bft_tick()


def test_outbound_bft_tick_prod_fails_closed_on_timeout_check_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_ExecutorTimeoutCheckBoom())
    with pytest.raises(BftOutboundBridgeError, match="timeout_check_failed"):
        loop._outbound_bft_tick()


def test_outbound_bft_tick_prod_fails_closed_on_vote_broadcast_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _mk_loop(_ExecutorDriveOutputs(), fail_broadcast=True)
    loop._last_bft_propose_ms = 10**18
    loop._last_bft_timeout_ms = 10**18
    with pytest.raises(BftOutboundBridgeError, match="vote_broadcast_failed"):
        loop._outbound_bft_tick()
