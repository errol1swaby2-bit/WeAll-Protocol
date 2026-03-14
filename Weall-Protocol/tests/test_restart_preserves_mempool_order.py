from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_restart_preserves_mempool_order(tmp_path: Path) -> None:
    """
    Restarting on the same DB must preserve pending tx ordering.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-mempool-order",
        tx_index_path=tx_index_path,
    )

    sub1 = ex1.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user1",
            "nonce": 1,
            "payload": {"pubkey": "k:user1"},
        }
    )
    sub2 = ex1.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user2",
            "nonce": 1,
            "payload": {"pubkey": "k:user2"},
        }
    )
    sub3 = ex1.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user3",
            "nonce": 1,
            "payload": {"pubkey": "k:user3"},
        }
    )

    assert sub1["ok"] is True
    assert sub2["ok"] is True
    assert sub3["ok"] is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-mempool-order",
        tx_index_path=tx_index_path,
    )

    mp = ex2.read_mempool()
    assert [tx["tx_id"] for tx in mp[:3]] == [
        sub1["tx_id"],
        sub2["tx_id"],
        sub3["tx_id"],
    ]
