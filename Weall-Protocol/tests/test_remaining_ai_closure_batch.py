from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from weall.ledger.state import LedgerView
from weall.net.net_loop import (
    BftInboundProcessingError,
    BftOutboundBridgeError,
    NetLoopConfig,
    NetMeshLoop,
)
from weall.runtime.apply.consensus import ConsensusApplyError, apply_consensus
from weall.runtime.bft_runtime_adapter import bft_drive_timeouts
from weall.runtime.tx_admission import TxEnvelope, admit_tx


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


class _NoopNode:
    cfg = SimpleNamespace(
        peer_id="local-peer",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="deadbeef",
    )

    def poll(self) -> None:
        return None


class _Mempool:
    def peek(self, limit: int):
        return []


class _Executor:
    chain_id = "chain-A"
    tx_index = None

    def snapshot(self):
        return {}

    def read_state(self):
        return {}


class _TimeoutFailureExecutor:
    def _local_validator_account(self) -> str:
        raise RuntimeError("local-validator-resolution-boom")


def _loop() -> NetMeshLoop:
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
    loop.node = _NoopNode()
    loop._stop = _StoppingEvent()
    loop._bft_enabled = True
    loop._seed_discovery_tick = lambda: None
    loop._dial_peers_tick = lambda: None
    loop._addr_gossip_tick = lambda: None
    loop._relay_poll_tick = lambda: None
    loop._outbound_tx_gossip_tick = lambda: None
    loop._record_net_metric_gauges = lambda: None
    return loop


def test_net_loop_prod_surfaces_bft_fetch_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _loop()
    loop._bft_fetch_tick = lambda: (_ for _ in ()).throw(RuntimeError("fetch boom"))
    loop._outbound_bft_tick = lambda: None

    with pytest.raises(BftInboundProcessingError, match="bft_fetch_tick_failed"):
        loop._run()


def test_net_loop_prod_surfaces_bft_outbound_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = _loop()
    loop._bft_fetch_tick = lambda: None
    loop._outbound_bft_tick = lambda: (_ for _ in ()).throw(RuntimeError("outbound boom"))

    with pytest.raises(BftOutboundBridgeError, match="bft_outbound_tick_failed"):
        loop._run()


def test_timeout_adapter_prod_does_not_swallow_pacemaker_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_AUTOTIMEOUT", "1")
    with pytest.raises(RuntimeError, match="local-validator-resolution-boom"):
        bft_drive_timeouts(_TimeoutFailureExecutor(), now_ms=1)


def test_timeout_adapter_nonprod_retains_best_effort_compatibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_AUTOTIMEOUT", "1")
    assert bft_drive_timeouts(_TimeoutFailureExecutor(), now_ms=1) == []


def _bft_active_state() -> dict:
    return {
        "chain_id": "chain-A",
        "height": 5,
        "accounts": {"alice": {"nonce": 0}},
        "roles": {"validators": {"active_set": ["alice"]}},
        "consensus": {
            "validator_set": {"active_set": ["alice"], "epoch": 1},
            "phase": {"current": "bft_active", "history": []},
        },
    }


def _legacy_block_propose_env() -> TxEnvelope:
    return TxEnvelope(
        tx_type="BLOCK_PROPOSE",
        signer="alice",
        nonce=1,
        payload={"block_id": "legacy-b6", "height": 6, "proposer": "alice"},
        sig="",
        system=False,
    )


def test_block_propose_is_not_admissible_during_hotstuff_bft() -> None:
    state = _bft_active_state()
    verdict = admit_tx(
        _legacy_block_propose_env(),
        LedgerView.from_ledger(state),
        canon=None,
        context="block",
    )
    assert verdict.ok is False
    assert verdict.code == "legacy_consensus_tx_disabled"
    assert verdict.reason == "block_propose_disabled_under_hotstuff_bft"


def test_block_propose_apply_backstop_rejects_without_mutation_during_hotstuff_bft() -> None:
    state = _bft_active_state()
    before = deepcopy(state)
    with pytest.raises(ConsensusApplyError, match="block_propose_disabled_under_hotstuff_bft"):
        apply_consensus(state, _legacy_block_propose_env())
    assert state == before


def test_semantic_review_material_ignores_only_volatile_source_line() -> None:
    import sys

    scripts = Path(__file__).resolve().parents[1] / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        from v2_spec_validation import compact_digest, tx_review_material
    finally:
        sys.path.pop(0)

    base = {
        "stable_id": "TX-X",
        "numeric_id": 1,
        "tx_type": "EXAMPLE",
        "domain": "Example",
        "origin": "USER",
        "context": "mempool",
        "signer": "envelope_signer",
        "authority": "origin:USER",
        "poh_gate": "none",
        "role_gate": "none",
        "conflict_rules": {},
        "state_reads": ["key:a"],
        "state_writes": ["key:b"],
        "system_followups": [],
        "receipt_contract": {},
        "failure_codes": [],
        "replay_behavior": "deterministic",
        "activation": {},
        "migration_treatment": "preserve",
        "implementation_source": {
            "path": "src/weall/runtime/example.py",
            "function": "apply_example",
            "handler": "example",
            "line": 10,
        },
        "primary_mechanism_id": "M-X",
    }
    shifted = deepcopy(base)
    shifted["implementation_source"]["line"] = 999
    changed = deepcopy(base)
    changed["implementation_source"]["function"] = "apply_other"

    assert compact_digest(tx_review_material(base)) == compact_digest(tx_review_material(shifted))
    assert compact_digest(tx_review_material(base)) != compact_digest(tx_review_material(changed))
