# tests/test_e2e_two_node_convergence.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_two_node_convergence_smoke(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")

    ex_a = WeAllExecutor(db_path=db_a, node_id="@alice", chain_id="conv", tx_index_path=tx_index_path)
    ex_b = WeAllExecutor(db_path=db_b, node_id="@bob", chain_id="conv", tx_index_path=tx_index_path)

    # Seed with one tx and produce a block on node A.
    assert ex_a.submit_tx(
        {"tx_type": "ACCOUNT_REGISTER", "signer": "@usera", "nonce": 1, "payload": {"pubkey": "k:usera"}}
    )["ok"] is True
    assert ex_a.produce_block(max_txs=1).ok is True

    # Node B produces empty; the goal here is simply that both nodes can run independently.
    assert ex_b.produce_block(max_txs=1).ok is True


def test_executor_refuses_chain_id_mismatch(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=tx_index_path)
    assert ex.submit_tx(
        {"tx_type": "ACCOUNT_REGISTER", "signer": "@user0", "nonce": 1, "payload": {"pubkey": "k:user0"}}
    )["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    # Re-open the same DB with a different chain_id must fail-closed
    with pytest.raises(ExecutorError):
        WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="chain-B", tx_index_path=tx_index_path)
