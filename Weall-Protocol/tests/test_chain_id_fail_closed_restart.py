from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_restart_with_different_chain_id_fails_closed(tmp_path: Path) -> None:
    """
    If a DB was initialized for one chain_id, reopening it under another
    chain_id must fail closed.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="chain-A",
        tx_index_path=tx_index_path,
    )

    assert ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:alice"},
        }
    )["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    with pytest.raises(ExecutorError):
        WeAllExecutor(
            db_path=db_path,
            node_id="@alice",
            chain_id="chain-B",
            tx_index_path=tx_index_path,
        )
