from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_confirmed_tx_not_reincluded_after_restart(tmp_path: Path) -> None:
    """
    After a tx is confirmed and the node restarts, subsequent block production
    must not include that already-confirmed tx again.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="no-reinclude-after-restart",
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
    assert sub1["ok"] is True

    meta1 = ex1.produce_block(max_txs=1)
    assert meta1.ok is True
    assert int(meta1.applied_count) == 1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="no-reinclude-after-restart",
        tx_index_path=tx_index_path,
    )

    # Add a different valid tx so a new block can still be produced.
    sub2 = ex2.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@u2",
            "nonce": 1,
            "payload": {"pubkey": "k:u2"},
        }
    )
    assert sub2["ok"] is True

    meta2 = ex2.produce_block(max_txs=10)
    assert meta2.ok is True
    assert int(meta2.applied_count) == 1

    tx1 = ex2.get_tx_status(sub1["tx_id"])
    tx2 = ex2.get_tx_status(sub2["tx_id"])

    assert tx1["status"] == "confirmed"
    assert tx2["status"] == "confirmed"

    # Only one new tx should have been applied in the second block.
    assert int(meta2.applied_count) == 1
