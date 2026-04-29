from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_mempool_survives_restart_before_commit(tmp_path: Path) -> None:
    """
    If txs are pending but no block has been committed yet, restarting the
    executor must preserve the pending mempool.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="restart-before-commit",
        tx_index_path=tx_index_path,
    )

    sub1 = ex1.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@u1",
            "nonce": 1,
            "payload": {"pubkey": "k:u1"},
        }
    )
    sub2 = ex1.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@u2",
            "nonce": 1,
            "payload": {"pubkey": "k:u2"},
        }
    )

    assert sub1["ok"] is True
    assert sub2["ok"] is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="restart-before-commit",
        tx_index_path=tx_index_path,
    )

    mp = ex2.read_mempool()
    tx_ids = [t["tx_id"] for t in mp]

    assert sub1["tx_id"] in tx_ids
    assert sub2["tx_id"] in tx_ids
    assert len(tx_ids) == 2
