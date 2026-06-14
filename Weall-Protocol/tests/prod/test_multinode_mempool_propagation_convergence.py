from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

from weall.net.net_loop import NetMeshLoop
from weall.runtime.mempool import PersistentMempool, compute_tx_id
from weall.runtime.sqlite_db import SqliteDB

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rehearse_genesis_observer_promoted_validator_mempool_v1_5.py"


def _load_harness_module():
    spec = importlib.util.spec_from_file_location("b615_rehearsal", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tx(signer: str, nonce: int, chain_id: str = "chain-b615") -> dict:
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": nonce,
        "payload": {"pubkey": f"pubkey:{signer}"},
        "chain_id": chain_id,
    }


def test_batch615_multinode_mempool_converges_before_commit_and_clears_after_restart(tmp_path: Path) -> None:
    mod = _load_harness_module()
    report = mod.run_harness(work_dir=tmp_path / "rehearsal")

    assert report["ok"] is True, report
    mempool = report["mempool"]
    assert mempool["canonical_converged_before_commit"] is True
    assert mempool["duplicate_replay_ignored"] is True
    assert mempool["invalid_wrong_chain_rejected"] is True
    assert mempool["nonce_conflict_rejected"] is True

    before = mempool["before_commit"]
    ids = before["genesis"]["tx_ids"]
    assert ids == before["observer"]["tx_ids"] == before["promoted_validator"]["tx_ids"]
    assert len(ids) == 3

    assert all(node["size"] == 0 for node in mempool["after_commit"].values())
    assert all(node["size"] == 0 for node in mempool["after_restart"].values())

    block = report["block_finalization"]
    assert block["state_converged_after_commit"] is True
    assert block["state_converged_after_restart"] is True
    assert len(set(block["roots_after_restart"].values())) == 1


def test_batch615_canonical_mempool_selection_is_arrival_order_independent(tmp_path: Path) -> None:
    txs = [_tx("@carol", 1), _tx("@alice", 1), _tx("@bob", 1)]
    pool_a = PersistentMempool(db=SqliteDB(path=str(tmp_path / "a.sqlite")), chain_id="chain-b615")
    pool_b = PersistentMempool(db=SqliteDB(path=str(tmp_path / "b.sqlite")), chain_id="chain-b615")

    for tx in txs:
        assert pool_a.add(dict(tx))["ok"] is True
    for tx in reversed(txs):
        assert pool_b.add(dict(tx))["ok"] is True

    selected_a = [tx["tx_id"] for tx in pool_a.fetch_for_block(limit=10, policy="canonical")]
    selected_b = [tx["tx_id"] for tx in pool_b.fetch_for_block(limit=10, policy="canonical")]
    assert selected_a == selected_b
    assert [tx["signer"] for tx in pool_a.fetch_for_block(limit=10, policy="canonical")] == [
        "@alice",
        "@bob",
        "@carol",
    ]


def test_batch615_outbound_tx_gossip_seen_cache_uses_chain_bound_tx_id(monkeypatch) -> None:
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": "pubkey:alice"},
    }
    chain_id = "chain-b615-seen-cache"
    expected_seen_id = compute_tx_id(tx, chain_id=chain_id)
    broadcasts: list[object] = []

    class _Pool:
        def peek(self, _limit: int):
            return [dict(tx)]

    executor = type("_Executor", (), {"chain_id": chain_id})()

    loop = NetMeshLoop(executor=executor, mempool=_Pool(), cfg=None)
    loop.node = SimpleNamespace(
        cfg=SimpleNamespace(chain_id=chain_id, schema_version="1", tx_index_hash="tx-index"),
        broadcast_message=lambda msg: broadcasts.append(msg),
    )
    loop._tx_seen[expected_seen_id] = 9_999_999_999_999
    loop._last_tx_gossip_ms = 0

    loop._outbound_tx_gossip_tick()

    assert broadcasts == []
