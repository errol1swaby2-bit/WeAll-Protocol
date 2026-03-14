from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_confirmed_tx_status_persists_across_restart(tmp_path: Path) -> None:
    """
    A tx confirmed before restart must still resolve as confirmed afterward.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-tx-status",
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

    assert ex.get_tx_status(tx_id)["status"] == "pending"

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True

    before = ex.get_tx_status(tx_id)
    assert before["status"] == "confirmed"
    assert int(before["height"]) == 1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-tx-status",
        tx_index_path=tx_index_path,
    )

    after = ex2.get_tx_status(tx_id)
    assert after["status"] == "confirmed"
    assert int(after["height"]) == 1
    assert after["tx_id"] == tx_id
