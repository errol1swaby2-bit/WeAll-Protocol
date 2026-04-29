from __future__ import annotations

from weall.runtime.block_admission import _is_descendant


def _chain(depth: int) -> dict[str, dict[str, str]]:
    blocks: dict[str, dict[str, str]] = {"GENESIS": {"block_id": "GENESIS", "prev_block_id": ""}}
    prev = "GENESIS"
    for i in range(1, depth + 1):
        bid = f"B{i}"
        blocks[bid] = {"block_id": bid, "prev_block_id": prev}
        prev = bid
    return blocks


def test_block_admission_ancestry_is_unbounded_for_long_honest_chain_batch89() -> None:
    blocks = _chain(50_100)
    assert _is_descendant(blocks, candidate="B50100", ancestor="B1") is True


def test_block_admission_ancestry_rejects_cycle_batch89() -> None:
    blocks = {
        "A": {"block_id": "A", "prev_block_id": "C"},
        "B": {"block_id": "B", "prev_block_id": "A"},
        "C": {"block_id": "C", "prev_block_id": "B"},
    }
    assert _is_descendant(blocks, candidate="A", ancestor="Z") is False


def test_block_admission_ancestry_supports_legacy_record_shape_batch89() -> None:
    blocks = {
        "A": {"prev": ""},
        "B": {"prev": "A"},
        "C": {"prev": "B"},
    }
    assert _is_descendant(blocks, candidate="C", ancestor="A") is True
