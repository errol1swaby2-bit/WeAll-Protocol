from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor, ExecutorError


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_refuse_to_mix_chain_ids_in_same_db(tmp_path: Path) -> None:
    """SQLite migration safety:

    If a DB already contains state for chain_id A, starting with chain_id B must fail closed.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="A", tx_index_path=tx_index_path)
    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "u0", "nonce": 1, "payload": {}})["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    with pytest.raises(ExecutorError):
        WeAllExecutor(db_path=db_path, node_id="alice", chain_id="B", tx_index_path=tx_index_path)
