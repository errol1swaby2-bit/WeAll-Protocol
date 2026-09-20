from __future__ import annotations

from weall.runtime.block_hash import compute_block_hash
from weall.runtime.block_id import compute_block_id
from weall.runtime.executor import WeAllExecutor


def _block(
    *,
    label: str,
    height: int,
    prev_block_id: str = "",
    prev_block_hash: str = "",
    receipts_root: str = "22" * 32,
    ts_ms: int | None = None,
) -> dict:
    block_ts_ms = int(ts_ms if ts_ms is not None else 1000 + (height * 1000))
    header = {
        "chain_id": "weall:test",
        "height": int(height),
        "prev_block_hash": str(prev_block_hash),
        "block_ts_ms": block_ts_ms,
        "tx_ids": [],
        "receipts_root": str(receipts_root),
        "state_root": f"sr:{label}",
    }
    block_hash = compute_block_hash(header=header)
    block_id = compute_block_id(
        chain_id="weall:test",
        height=int(height),
        prev_block_id=prev_block_id,
        prev_block_hash=str(prev_block_hash),
        ts_ms=block_ts_ms,
        tx_ids=[],
        receipts_root=str(receipts_root),
    )
    return {
        "block_id": block_id,
        "block_hash": block_hash,
        "height": int(height),
        "prev_block_id": prev_block_id,
        "block_ts_ms": block_ts_ms,
        "header": header,
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

    blk = _block(label="blk-1", height=1)
    assert ex.bft_cache_remote_block(blk, expected_block_hash=str(blk["block_hash"])) is True

    diag = ex.bft_diagnostics()
    assert diag["pending_remote_blocks"] == [blk["block_id"]]
    assert diag["pending_remote_block_hashes"] == [blk["block_hash"]]
    assert diag["pending_remote_block_hashes_count"] == 1
    assert ex._known_block_id_for_hash(str(blk["block_hash"])) == blk["block_id"]


def test_pending_remote_block_order_uses_block_hash_as_tie_breaker(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )

    blk_b = _block(
        label="blk-b",
        height=2,
        prev_block_id="parent",
        prev_block_hash="33" * 32,
        receipts_root="44" * 32,
    )
    blk_a = _block(
        label="blk-a",
        height=2,
        prev_block_id="parent",
        prev_block_hash="33" * 32,
        receipts_root="55" * 32,
    )

    assert ex.bft_cache_remote_block(blk_b, expected_block_hash=str(blk_b["block_hash"])) is True
    assert ex.bft_cache_remote_block(blk_a, expected_block_hash=str(blk_a["block_hash"])) is True

    expected = sorted(
        (blk_a, blk_b),
        key=lambda block: (
            int(block["height"]),
            str(block["block_hash"]),
            str(block["block_id"]),
        ),
    )
    diag = ex.bft_diagnostics()
    assert diag["pending_remote_blocks"] == [block["block_id"] for block in expected]
    assert diag["pending_remote_block_hashes"] == [block["block_hash"] for block in expected]
