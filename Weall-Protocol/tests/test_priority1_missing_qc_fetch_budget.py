from __future__ import annotations

from collections import OrderedDict
from types import MethodType

from weall.runtime.executor import WeAllExecutor


def _make_executor() -> WeAllExecutor:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex.state = {
        "tip": "A",
        "blocks": {
            "A": {"block_id": "A", "height": 1, "block_hash": "A-h"},
        },
    }
    ex._pending_missing_qcs = OrderedDict()
    ex._pending_remote_blocks = OrderedDict()
    ex._max_missing_qc_fetches_per_call = 2
    ex._max_missing_parent_fetches_per_call = 2
    ex._missing_qc_fetch_cursor = 0
    ex._missing_parent_fetch_cursor = 0
    ex._pending_missing_qc_entries = MethodType(
        lambda self: OrderedDict((k, dict(v)) for k, v in self._pending_missing_qcs.items()), ex
    )
    ex._pending_missing_qc_json = MethodType(
        lambda self, *, block_id="", block_hash="": (
            dict(self._pending_missing_qcs.get(str(block_id or ""), {}))
            if str(block_id or "") in self._pending_missing_qcs
            else None
        ),
        ex,
    )
    ex._bft_pending_block_json = MethodType(
        lambda self, bid: self._pending_remote_blocks.get(str(bid or "")), ex
    )
    ex._has_local_block = MethodType(
        lambda self, bid: str(bid or "") in self.state.get("blocks", {}), ex
    )
    ex._ordered_pending_block_ids = MethodType(
        lambda self: list(self._pending_remote_blocks.keys()), ex
    )
    ex._block_height_hint = MethodType(
        lambda self, blk: int(blk.get("height") or 0) if isinstance(blk, dict) else 0,
        ex,
    )
    return ex


def test_missing_qc_fetches_are_bounded_and_rotate_batch108() -> None:
    ex = _make_executor()
    ex._pending_missing_qcs = OrderedDict(
        (
            ("Q1", {"block_id": "Q1", "block_hash": "Q1-h"}),
            ("Q2", {"block_id": "Q2", "block_hash": "Q2-h"}),
            ("Q3", {"block_id": "Q3", "block_hash": "Q3-h"}),
        )
    )
    ex._pending_remote_blocks = OrderedDict(
        (
            (
                "C1",
                {
                    "block_id": "C1",
                    "prev_block_id": "P1",
                    "height": 3,
                    "header": {"prev_block_hash": "P1-h"},
                },
            ),
            (
                "C2",
                {
                    "block_id": "C2",
                    "prev_block_id": "P2",
                    "height": 3,
                    "header": {"prev_block_hash": "P2-h"},
                },
            ),
        )
    )

    first = ex.bft_pending_fetch_request_descriptors()
    assert [d["reason"] for d in first] == [
        "missing_qc_block",
        "missing_qc_block",
        "missing_parent",
        "missing_parent",
    ]
    assert [d["block_id"] for d in first[:2]] == ["Q1", "Q2"]
    assert [d["block_id"] for d in first[2:]] == ["P1", "P2"]
    assert ex._missing_qc_fetch_cursor == 2
    assert ex._missing_parent_fetch_cursor == 0

    second = ex.bft_pending_fetch_request_descriptors()
    assert [d["block_id"] for d in second[:2]] == ["Q3", "Q1"]
    assert [d["block_id"] for d in second[2:]] == ["P1", "P2"]
    assert ex._missing_qc_fetch_cursor == 1
    assert ex._missing_parent_fetch_cursor == 0


def test_missing_qc_fetch_cursor_resets_when_backlog_clears_batch108() -> None:
    ex = _make_executor()
    ex._pending_missing_qcs = OrderedDict(
        (
            ("Q1", {"block_id": "Q1", "block_hash": "Q1-h"}),
            ("Q2", {"block_id": "Q2", "block_hash": "Q2-h"}),
            ("Q3", {"block_id": "Q3", "block_hash": "Q3-h"}),
        )
    )

    first = ex.bft_pending_fetch_request_descriptors()
    assert [d["block_id"] for d in first] == ["Q1", "Q2"]
    assert ex._missing_qc_fetch_cursor == 2

    ex._pending_missing_qcs = OrderedDict((("Q3", {"block_id": "Q3", "block_hash": "Q3-h"}),))
    second = ex.bft_pending_fetch_request_descriptors()
    assert [d["block_id"] for d in second] == ["Q3"]
    assert ex._missing_qc_fetch_cursor == 0
