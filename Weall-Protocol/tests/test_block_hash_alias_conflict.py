from __future__ import annotations

from weall.runtime.executor import WeAllExecutor


def test_remote_block_cache_rejects_block_hash_reused_by_different_block_id(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )

    ex.state["blocks"] = {
        "known-id": {
            "height": 1,
            "prev_block_id": "",
            "block_ts_ms": 1000,
            "block_hash": "hash-same",
        }
    }

    alias = {
        "block_id": "different-id",
        "height": 2,
        "prev_block_id": "known-id",
        "block_hash": "hash-same",
        "block_ts_ms": 2000,
        "header": {
            "chain_id": "weall:test",
            "height": 2,
            "prev_block_hash": "hash-same",
            "block_ts_ms": 2000,
            "tx_ids": [],
            "receipts_root": "",
            "state_root": "sr",
        },
        "txs": [],
        "receipts": [],
    }

    assert ex.bft_cache_remote_block(alias) is False
    diag = ex.bft_diagnostics()
    assert diag["conflicted_block_hashes_count"] == 1
    assert "hash-same" in diag["conflicted_block_hashes"]


def test_pending_remote_block_hash_alias_is_fail_closed(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )

    first = {
        "block_id": "blk-a",
        "height": 1,
        "prev_block_id": "",
        "block_hash": "shared-hash",
        "block_ts_ms": 1000,
        "header": {
            "chain_id": "weall:test",
            "height": 1,
            "prev_block_hash": "",
            "block_ts_ms": 1000,
            "tx_ids": [],
            "receipts_root": "",
            "state_root": "s1",
        },
        "txs": [],
        "receipts": [],
    }
    second = {
        "block_id": "blk-b",
        "height": 2,
        "prev_block_id": "blk-a",
        "block_hash": "shared-hash",
        "block_ts_ms": 2000,
        "header": {
            "chain_id": "weall:test",
            "height": 2,
            "prev_block_hash": "shared-hash",
            "block_ts_ms": 2000,
            "tx_ids": [],
            "receipts_root": "",
            "state_root": "s2",
        },
        "txs": [],
        "receipts": [],
    }

    assert ex.bft_cache_remote_block(first) is True
    assert ex.bft_cache_remote_block(second) is False
    assert ex.bft_pending_fetch_requests() == []
    diag = ex.bft_diagnostics()
    assert diag["conflicted_block_hashes_count"] == 1
