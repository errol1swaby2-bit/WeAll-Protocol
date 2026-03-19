from __future__ import annotations

from weall.runtime.block_id import compute_block_id


def test_block_id_changes_when_tx_order_changes() -> None:
    a = compute_block_id(
        chain_id="weall:test",
        height=2,
        prev_block_id="b1",
        prev_block_hash="aa" * 32,
        ts_ms=123456,
        node_id="n1",
        tx_ids=["tx1", "tx2"],
        receipts_root="11" * 32,
    )
    b = compute_block_id(
        chain_id="weall:test",
        height=2,
        prev_block_id="b1",
        prev_block_hash="aa" * 32,
        ts_ms=123456,
        node_id="n1",
        tx_ids=["tx2", "tx1"],
        receipts_root="11" * 32,
    )
    assert a != b


def test_block_id_changes_when_receipts_root_changes() -> None:
    a = compute_block_id(
        chain_id="weall:test",
        height=2,
        prev_block_id="b1",
        prev_block_hash="aa" * 32,
        ts_ms=123456,
        node_id="n1",
        tx_ids=["tx1"],
        receipts_root="11" * 32,
    )
    b = compute_block_id(
        chain_id="weall:test",
        height=2,
        prev_block_id="b1",
        prev_block_hash="aa" * 32,
        ts_ms=123456,
        node_id="n1",
        tx_ids=["tx1"],
        receipts_root="22" * 32,
    )
    assert a != b
