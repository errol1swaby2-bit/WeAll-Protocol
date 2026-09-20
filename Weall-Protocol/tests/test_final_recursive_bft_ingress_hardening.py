from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.net_loop import NetLoopConfig, NetLoopRuntimeError, NetMeshLoop, NetPeerConfigError
from weall.runtime.bft_hotstuff import BftTimeout, BftVote, HotStuffBFT


def _vote_json() -> dict:
    return {
        "t": "VOTE",
        "chain_id": "chain-A",
        "view": 1,
        "block_id": "block-1",
        "block_hash": "a" * 64,
        "parent_id": "genesis",
        "signer": "victim",
        "pubkey": "victim-pub",
        "sig": "invalid-until-monkeypatched",
        "validator_epoch": 1,
        "validator_set_hash": "set-1",
    }


def _timeout_json() -> dict:
    return {
        "t": "TIMEOUT",
        "chain_id": "chain-A",
        "view": 1,
        "high_qc_id": "genesis",
        "signer": "victim",
        "pubkey": "victim-pub",
        "sig": "invalid-until-monkeypatched",
        "validator_epoch": 1,
        "validator_set_hash": "set-1",
    }


def test_unverified_vote_cannot_consume_verified_sender_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = HotStuffBFT(chain_id="chain-A")
    calls: list[dict] = []

    monkeypatch.setattr(BftVote, "verify", lambda self: False)

    assert (
        engine.accept_vote(
            vote_json=_vote_json(),
            validators=["victim"],
            vpub={"victim": "victim-pub"},
            verified_admission=lambda artifact: calls.append(dict(artifact)) or True,
        )
        is None
    )
    assert calls == []
    assert engine._votes == {}


def test_verified_vote_budget_rejection_happens_before_vote_cache_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = HotStuffBFT(chain_id="chain-A")
    calls: list[dict] = []

    monkeypatch.setattr(BftVote, "verify", lambda self: True)

    assert (
        engine.accept_vote(
            vote_json=_vote_json(),
            validators=["victim"],
            vpub={"victim": "victim-pub"},
            verified_admission=lambda artifact: calls.append(dict(artifact)) or False,
        )
        is None
    )
    assert len(calls) == 1
    assert calls[0]["signer"] == "victim"
    assert engine._votes == {}


def test_unverified_timeout_cannot_consume_verified_sender_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = HotStuffBFT(chain_id="chain-A")
    calls: list[dict] = []

    monkeypatch.setattr(BftTimeout, "verify", lambda self: False)

    assert (
        engine.accept_timeout(
            timeout_json=_timeout_json(),
            validators=["victim"],
            vpub={"victim": "victim-pub"},
            verified_admission=lambda artifact: calls.append(dict(artifact)) or True,
        )
        is None
    )
    assert calls == []
    assert engine._timeouts == {}


class _StoppingEvent:
    def __init__(self) -> None:
        self.calls = 0

    def is_set(self) -> bool:
        self.calls += 1
        return self.calls > 1


class _Node:
    cfg = SimpleNamespace(
        peer_id="local-peer",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="deadbeef",
    )

    def poll(self) -> None:
        return None


class _Executor:
    chain_id = "chain-A"

    def snapshot(self):
        return {}

    def read_state(self):
        return {}


class _Mempool:
    def peek(self, limit: int):
        return []


def _net_loop() -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=_Executor(),
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=1,
            schema_version="1",
        ),
    )
    loop.node = _Node()
    loop._stop = _StoppingEvent()
    loop._bft_enabled = False
    loop._relay_poll_tick = lambda: None
    loop._outbound_tx_gossip_tick = lambda: None
    loop._record_net_metric_gauges = lambda: None
    return loop


@pytest.mark.parametrize(
    ("failed_tick", "error"),
    [
        ("_seed_discovery_tick", NetPeerConfigError("peer_store_merge_failed")),
        ("_dial_peers_tick", NetPeerConfigError("peer_list_read_failed")),
        ("_addr_gossip_tick", RuntimeError("peer_addr_broadcast_failed")),
    ],
)
def test_prod_network_control_plane_failure_is_not_silently_swallowed(
    monkeypatch: pytest.MonkeyPatch,
    failed_tick: str,
    error: Exception,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _net_loop()
    loop._seed_discovery_tick = lambda: None
    loop._dial_peers_tick = lambda: None
    loop._addr_gossip_tick = lambda: None
    setattr(loop, failed_tick, lambda: (_ for _ in ()).throw(error))

    with pytest.raises(NetLoopRuntimeError):
        loop._run()
