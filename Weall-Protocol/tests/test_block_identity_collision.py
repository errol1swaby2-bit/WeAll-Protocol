from __future__ import annotations

from weall.runtime.executor import WeAllExecutor


def test_remote_block_cache_rejects_block_id_hash_collision(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )

    ex.state["blocks"] = {
        "same-id": {
            "height": 1,
            "prev_block_id": "",
            "block_ts_ms": 1000,
            "block_hash": "hash-a",
        }
    }

    conflict = {
        "block_id": "same-id",
        "height": 2,
        "prev_block_id": "same-id",
        "block_hash": "hash-b",
        "block_ts_ms": 2000,
        "header": {
            "chain_id": "weall:test",
            "height": 2,
            "prev_block_hash": "hash-a",
            "block_ts_ms": 2000,
            "tx_ids": [],
            "receipts_root": "",
            "state_root": "sr",
        },
        "txs": [],
        "receipts": [],
    }

    assert ex.bft_cache_remote_block(conflict) is False
