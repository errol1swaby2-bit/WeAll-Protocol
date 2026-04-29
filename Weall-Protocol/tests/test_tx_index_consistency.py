from __future__ import annotations

import sqlite3
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_tx_index_matches_block_contents(tmp_path: Path) -> None:
    """
    Ensure every committed tx has a tx_index entry
    and metadata matches block contents.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-index-test",
        tx_index_path=tx_index_path,
    )

    # submit several independent txs
    for i in range(5):
        res = ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": f"@user{i}",
                "nonce": 1,
                "payload": {"pubkey": f"k:{i}"},
            }
        )
        assert res["ok"] is True

    for _ in range(5):
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row

    rows = con.execute("SELECT * FROM tx_index").fetchall()

    assert len(rows) == 5

    seen = set()

    for r in rows:
        tx_id = r["tx_id"]

        assert tx_id not in seen
        seen.add(tx_id)

        assert r["height"] > 0
        assert r["block_id"]
        assert r["tx_type"] == "ACCOUNT_REGISTER"
        assert r["ok"] == 1

    heights = [r["height"] for r in rows]

    assert sorted(heights) == [1, 2, 3, 4, 5]


def test_tx_index_ordering(tmp_path: Path) -> None:
    """
    Ensure ordering by height works as expected.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="tx-index-order",
        tx_index_path=tx_index_path,
    )

    for i in range(3):
        res = ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": f"@u{i}",
                "nonce": 1,
                "payload": {"pubkey": f"k:{i}"},
            }
        )
        assert res["ok"]

    for _ in range(3):
        meta = ex.produce_block(max_txs=1)
        assert meta.ok

    con = sqlite3.connect(db_path)
    rows = con.execute("SELECT height FROM tx_index ORDER BY height DESC").fetchall()

    heights = [r[0] for r in rows]

    assert heights == [3, 2, 1]
