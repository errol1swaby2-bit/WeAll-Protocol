from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_mempool_persists_across_restart(tmp_path: Path) -> None:
    """
    Accepted but uncommitted txs should remain in mempool after restart.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="mempool-restart",
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

    mp1 = ex.read_mempool()
    ids1 = {item["tx_id"] for item in mp1}
    assert sub1["tx_id"] in ids1
    assert sub2["tx_id"] in ids1
    assert len(mp1) == 2

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="mempool-restart",
        tx_index_path=tx_index_path,
    )

    mp2 = ex2.read_mempool()
    ids2 = {item["tx_id"] for item in mp2}
    assert sub1["tx_id"] in ids2
    assert sub2["tx_id"] in ids2
    assert len(mp2) == 2
