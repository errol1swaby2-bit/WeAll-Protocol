from __future__ import annotations

from weall.runtime.executor import WeAllExecutor


def _block(*, block_id: str, block_hash: str, height: int, prev_block_id: str = "") -> dict:
    prev_hash = ""
    if prev_block_id:
        prev_hash = f"prev:{prev_block_id}"
    return {
        "block_id": block_id,
        "block_hash": block_hash,
        "height": height,
        "prev_block_id": prev_block_id,
        "block_ts_ms": 1000 + (height * 1000),
        "header": {
            "chain_id": "weall:test",
            "height": height,
            "prev_block_hash": prev_hash,
            "block_ts_ms": 1000 + (height * 1000),
            "tx_ids": [],
            "receipts_root": "",
            "state_root": f"sr:{block_id}",
        },
        "txs": [],
        "receipts": [],
    }


def test_pending_remote_block_hashes_are_exposed_and_reverse_indexed(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )

    blk = _block(block_id="blk-1", block_hash="hash-1", height=1)
    assert ex.bft_cache_remote_block(blk) is True

    diag = ex.bft_diagnostics()
    assert diag["pending_remote_blocks"] == ["blk-1"]
    assert diag["pending_remote_block_hashes"] == ["hash-1"]
    assert diag["pending_remote_block_hashes_count"] == 1
    assert ex._known_block_id_for_hash("hash-1") == "blk-1"


def test_pending_remote_block_order_uses_block_hash_as_tie_breaker(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )

    blk_b = _block(block_id="blk-b", block_hash="hash-b", height=2, prev_block_id="parent")
    blk_a = _block(block_id="blk-a", block_hash="hash-a", height=2, prev_block_id="parent")

    assert ex.bft_cache_remote_block(blk_b) is True
    assert ex.bft_cache_remote_block(blk_a) is True

    diag = ex.bft_diagnostics()
    assert diag["pending_remote_blocks"] == ["blk-a", "blk-b"]
    assert diag["pending_remote_block_hashes"] == ["hash-a", "hash-b"]
