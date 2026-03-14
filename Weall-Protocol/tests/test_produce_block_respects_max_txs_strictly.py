from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_produce_block_respects_max_txs_strictly(tmp_path: Path) -> None:
    """
    produce_block(max_txs=N) must not consume more than N valid txs.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="max-txs-strict",
        tx_index_path=tx_index_path,
    )

    submitted = []
    for i in range(5):
        sub = ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": f"@user{i}",
                "nonce": 1,
                "payload": {"pubkey": f"k:user{i}"},
            }
        )
        assert sub["ok"] is True
        submitted.append(sub["tx_id"])

    meta = ex.produce_block(max_txs=2)
    assert meta.ok is True
    assert int(meta.applied_count) == 2

    mp = ex.read_mempool()
    remaining_ids = [tx["tx_id"] for tx in mp]

    assert len(remaining_ids) == 3
    assert remaining_ids == submitted[2:]
