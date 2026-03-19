from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.messages import MsgType, TxEnvelopeMsg, WireHeader
from weall.net.net_loop import (
    NetLoopConfig,
    NetLoopRuntimeError,
    NetMeshLoop,
    TxGossipBridgeError,
    TxIngressProcessingError,
)


class _FakeNode:
    def __init__(self, *, fail_broadcast: bool = False, fail_poll: bool = False) -> None:
        self.cfg = SimpleNamespace(peer_id="local-peer", chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef")
        self.calls = []
        self._fail_broadcast = bool(fail_broadcast)
        self._fail_poll = bool(fail_poll)

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        if self._fail_broadcast:
            raise RuntimeError("broadcast boom")
        self.calls.append((msg, exclude_peer_id))
        return 1

    def poll(self) -> None:
        if self._fail_poll:
            raise RuntimeError("poll boom")


class _RejectingMempool:
    def add(self, tx) -> None:
        raise ValueError("add boom")


class _ListOnlyBrokenMempool:
    def peek(self, limit: int):
        raise ValueError("peek boom")

    def list(self):
        raise ValueError("list boom")


class _BadEntryMempool:
    def peek(self, limit: int):
        return ["not-a-tx"]


class _GoodTxMempool:
    def __init__(self) -> None:
        self._tx = {"tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "payload": {"email": "a@example.com"}, "chain_id": "chain-A", "sig": "00"}

    def peek(self, limit: int):
        return [self._tx]


class _ExecutorWithBadSnapshot:
    tx_index = None

    def snapshot(self):
        raise ValueError("snapshot boom")


class _ExecutorSimple:
    tx_index = None

    chain_id = "chain-A"

    def snapshot(self):
        return {}


class _StopAfterTxGossipLoop(NetMeshLoop):
    def __init__(self) -> None:
        super().__init__(
            executor=_ExecutorSimple(),
            mempool=_GoodTxMempool(),
            cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
        )
        self.node = _FakeNode()

    def _outbound_tx_gossip_tick(self) -> None:
        raise TxGossipBridgeError("tx_gossip_boom")


class _SinglePollFailNode(_FakeNode):
    def poll(self) -> None:
        raise RuntimeError("poll boom")


class _StoppingEvent:
    def __init__(self) -> None:
        self._calls = 0

    def is_set(self) -> bool:
        self._calls += 1
        return self._calls > 1

    def set(self) -> None:
        self._calls = 10**9

    def clear(self) -> None:
        self._calls = 0


def _mk_tx_msg() -> TxEnvelopeMsg:
    tx = {"tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "payload": {"email": "a@example.com"}, "chain_id": "chain-A", "sig": "00"}
    return TxEnvelopeMsg(header=WireHeader(type=MsgType.TX_ENVELOPE, chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef"), nonce=1, tx=tx)


def test_on_tx_prod_fails_closed_on_state_snapshot_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_ExecutorWithBadSnapshot(),
        mempool=_RejectingMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    monkeypatch.setattr(loop, "_state_snapshot", lambda: (_ for _ in ()).throw(ValueError("snapshot boom")))
    with pytest.raises(TxIngressProcessingError, match="tx_ingress_state_snapshot_failed"):
        loop._on_tx("peer1", _mk_tx_msg())


def test_on_tx_prod_fails_closed_on_mempool_add_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_ExecutorSimple(),
        mempool=_RejectingMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    monkeypatch.setattr("weall.net.net_loop.verify_tx_signature", lambda state, tx: True)
    monkeypatch.setattr("weall.net.net_loop.admit_tx", lambda **kwargs: SimpleNamespace(ok=True, code=None))
    with pytest.raises(TxIngressProcessingError, match="tx_ingress_mempool_add_failed"):
        loop._on_tx("peer1", _mk_tx_msg())


def test_outbound_tx_gossip_tick_prod_fails_closed_on_source_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_ExecutorSimple(),
        mempool=_ListOnlyBrokenMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode()
    loop._tx_gossip_interval_ms = 1
    loop._last_tx_gossip_ms = 0
    with pytest.raises(TxGossipBridgeError, match="tx_gossip_source_failed"):
        loop._outbound_tx_gossip_tick()


def test_outbound_tx_gossip_tick_prod_fails_closed_on_invalid_entry(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_ExecutorSimple(),
        mempool=_BadEntryMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode()
    loop._tx_gossip_interval_ms = 1
    loop._last_tx_gossip_ms = 0
    with pytest.raises(TxGossipBridgeError, match="tx_gossip_entry_not_object"):
        loop._outbound_tx_gossip_tick()


def test_outbound_tx_gossip_tick_prod_fails_closed_on_broadcast_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_ExecutorSimple(),
        mempool=_GoodTxMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode(fail_broadcast=True)
    loop._tx_gossip_interval_ms = 1
    loop._last_tx_gossip_ms = 0
    with pytest.raises(TxGossipBridgeError, match="tx_gossip_broadcast_failed"):
        loop._outbound_tx_gossip_tick()


def test_run_prod_fails_closed_on_node_poll_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_ExecutorSimple(),
        mempool=_GoodTxMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _SinglePollFailNode()
    loop._stop = _StoppingEvent()
    with pytest.raises(NetLoopRuntimeError, match="node_poll_failed"):
        loop._run()


def test_run_prod_fails_closed_on_tx_gossip_tick_error(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _StopAfterTxGossipLoop()
    loop._stop = _StoppingEvent()
    with pytest.raises(NetLoopRuntimeError, match="tx_gossip_tick_failed"):
        loop._run()
