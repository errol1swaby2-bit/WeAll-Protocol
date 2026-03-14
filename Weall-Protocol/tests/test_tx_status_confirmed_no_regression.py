from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_confirmed_tx_does_not_regress_to_pending_or_unknown(tmp_path: Path) -> None:
    """
    Once confirmed, a tx must remain confirmed across later blocks and restart.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-confirmed-no-regression",
        tx_index_path=tx_index_path,
    )

    sub1 = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:alice"},
        }
    )
    assert sub1["ok"] is True
    tx1 = sub1["tx_id"]

    assert ex.produce_block(max_txs=1).ok is True

    s1 = ex.get_tx_status(tx1)
    assert s1["status"] == "confirmed"
    assert int(s1["height"]) == 1

    sub2 = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@bob",
            "nonce": 1,
            "payload": {"pubkey": "k:bob"},
        }
    )
    assert sub2["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    s2 = ex.get_tx_status(tx1)
    assert s2["status"] == "confirmed"
    assert int(s2["height"]) == 1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-confirmed-no-regression",
        tx_index_path=tx_index_path,
    )

    s3 = ex2.get_tx_status(tx1)
    assert s3["status"] == "confirmed"
    assert int(s3["height"]) == 1
    assert s3["tx_id"] == tx1
