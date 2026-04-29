from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_tx_status_pending_then_confirmed_after_restart(tmp_path: Path) -> None:
    """
    A tx that is pending before restart and confirmed after restart should
    transition cleanly from pending -> confirmed.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="pending-then-confirmed",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user1",
            "nonce": 1,
            "payload": {"pubkey": "k:user1"},
        }
    )
    assert sub["ok"] is True
    tx_id = sub["tx_id"]

    s1 = ex.get_tx_status(tx_id)
    assert s1["status"] == "pending"

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="pending-then-confirmed",
        tx_index_path=tx_index_path,
    )

    s2 = ex2.get_tx_status(tx_id)
    assert s2["status"] == "pending"

    meta = ex2.produce_block(max_txs=1)
    assert meta.ok is True

    s3 = ex2.get_tx_status(tx_id)
    assert s3["status"] == "confirmed"
    assert int(s3["height"]) == 1
    assert s3["tx_id"] == tx_id
