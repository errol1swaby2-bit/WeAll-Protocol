from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.net_loop import NetLoopConfig, NetMeshLoop, TxGossipBridgeError


class _Exec:
    chain_id = "chain-A"

    def __init__(self) -> None:
        self.generation = 0

    def bft_branch_generation(self) -> int:
        return int(self.generation)

    def read_state(self):
        return {"height": 0}

    def tx_index_hash(self):
        return "deadbeef"

    def _schema_version(self):
        return "1"


class _Mempool:
    def __init__(self) -> None:
        self.tx = {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "alice-key"},
            "chain_id": "chain-A",
        }

    def peek(self, limit: int):
        return [dict(self.tx)]


class _Node:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            peer_id="local-peer",
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        )
        self.broadcasts = 0
        self.fail_broadcast = False

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        if self.fail_broadcast:
            raise RuntimeError("broadcast-failed")
        self.broadcasts += 1
        return 1


def _loop() -> tuple[NetMeshLoop, _Exec, _Node]:
    ex = _Exec()
    loop = NetMeshLoop(
        executor=ex,
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    node = _Node()
    loop.node = node
    loop._tx_gossip_interval_ms = 0
    loop._relay_client_enabled = False
    return loop, ex, node


def test_checkpoint_generation_allows_fresh_gossip_of_readmitted_tx(monkeypatch) -> None:
    loop, ex, node = _loop()
    ticks = iter((1_000, 2_000))
    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: next(ticks))

    loop._outbound_tx_gossip_tick()
    assert node.broadcasts == 1
    assert loop._tx_seen

    # Destructive checkpoint replacement clears the persistent mempool. If the
    # same tx is freshly re-admitted on the new branch, old branch-A transport
    # history must not suppress branch-B gossip.
    ex.generation += 1
    loop._outbound_tx_gossip_tick()

    assert node.broadcasts == 2


def test_failed_broadcast_does_not_poison_tx_retry_cache(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop, _ex, node = _loop()
    ticks = iter((1_000, 2_000))
    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: next(ticks))

    node.fail_broadcast = True
    with pytest.raises(TxGossipBridgeError, match="tx_gossip_broadcast_failed"):
        loop._outbound_tx_gossip_tick()

    # A failed transmission is not a completed gossip event and must not become
    # dedupe authority for the retry path.
    assert loop._tx_seen == {}

    node.fail_broadcast = False
    loop._outbound_tx_gossip_tick()
    assert node.broadcasts == 1


def test_failed_relay_submission_does_not_poison_tx_retry_cache(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop, _ex, node = _loop()
    ticks = iter((1_000, 2_000))
    monkeypatch.setattr("weall.net.net_loop._now_ms", lambda: next(ticks))

    calls = {"n": 0}

    def _relay(_msg):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("relay-failed")

    monkeypatch.setattr(loop, "_relay_submit_message", _relay)

    with pytest.raises(TxGossipBridgeError, match="tx_gossip_relay_submit_failed"):
        loop._outbound_tx_gossip_tick()

    assert node.broadcasts == 1
    assert loop._tx_seen == {}

    loop._outbound_tx_gossip_tick()
    assert node.broadcasts == 2
    assert calls["n"] == 2
    assert loop._tx_seen
