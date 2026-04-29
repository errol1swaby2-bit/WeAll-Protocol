from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_mempool_clears_only_committed_txs(tmp_path: Path) -> None:
    """
    Producing a block with max_txs=1 should remove only the committed tx,
    leaving the remainder pending in mempool.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="mempool-clear-partial",
        tx_index_path=tx_index_path,
    )

    sub1 = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user1",
            "nonce": 1,
            "payload": {"pubkey": "k:user1"},
        }
    )
    sub2 = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user2",
            "nonce": 1,
            "payload": {"pubkey": "k:user2"},
        }
    )

    assert sub1["ok"] is True
    assert sub2["ok"] is True

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    assert int(meta.applied_count) == 1

    mp = ex.read_mempool()
    ids = {item["tx_id"] for item in mp}

    assert len(mp) == 1
    assert (sub1["tx_id"] in ids) ^ (sub2["tx_id"] in ids)
