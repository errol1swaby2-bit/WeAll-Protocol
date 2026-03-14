from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_mempool_order_is_fifo_by_received_time(tmp_path: Path) -> None:
    """
    Pending tx selection should be stable and FIFO by receive order for equally valid txs.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="fifo-order",
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
    sub3 = ex.submit_tx(
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

    mp = ex.read_mempool()
    assert [tx["tx_id"] for tx in mp[:3]] == [
        sub1["tx_id"],
        sub2["tx_id"],
        sub3["tx_id"],
    ]
