from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_pending_tx_survives_restart(tmp_path: Path) -> None:
    """
    A tx accepted into mempool but not yet included in a block should still be
    visible as pending after restart.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-pending-restart",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:alice"},
        }
    )
    assert sub["ok"] is True
    tx_id = sub["tx_id"]

    before = ex.get_tx_status(tx_id)
    assert before["status"] == "pending"

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-pending-restart",
        tx_index_path=tx_index_path,
    )

    after = ex2.get_tx_status(tx_id)
    assert after["status"] == "pending"
    assert after["tx_id"] == tx_id
