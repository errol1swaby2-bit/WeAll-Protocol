from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.runtime.executor import ExecutorError


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_two_executors_with_separate_dbs_progress_independently(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")

    ex_a = WeAllExecutor(db_path=db_a, node_id="alice", chain_id="two-node", tx_index_path=tx_index_path)
    ex_b = WeAllExecutor(db_path=db_b, node_id="bob", chain_id="two-node", tx_index_path=tx_index_path)

    assert int(ex_a.read_state().get("height", 0)) == 0
    assert int(ex_b.read_state().get("height", 0)) == 0

    # Advance A only
    assert ex_a.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "userA", "nonce": 1, "payload": {}})["ok"] is True
    m = ex_a.produce_block(max_txs=1)
    assert m.ok is True
    assert m.height == 1

    assert int(ex_a.read_state().get("height", 0)) == 1
    assert int(ex_b.read_state().get("height", 0)) == 0


def test_executor_refuses_chain_id_mismatch(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="chain-A", tx_index_path=tx_index_path)
    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "user0", "nonce": 1, "payload": {}})["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    with pytest.raises(ExecutorError):
        WeAllExecutor(db_path=db_path, node_id="alice", chain_id="chain-B", tx_index_path=tx_index_path)
