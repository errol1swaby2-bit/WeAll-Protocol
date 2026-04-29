from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, monkeypatch) -> WeAllExecutor:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_MAX_MISSING_PARENT_FETCHES_PER_CALL", "3")
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="n1",
        chain_id="batch107",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _pending_block(*, block_id: str, parent_id: str, height: int) -> dict:
    return {
        "chain_id": "batch107",
        "block_id": block_id,
        "prev_block_id": parent_id,
        "height": int(height),
        "txs": [],
        "block_ts_ms": 1000 + int(height),
    }


def test_missing_parent_fetch_requests_are_bounded_and_rotating_batch107(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)
    ex._put_pending_missing_qc(
        {
            "t": "QC",
            "chain_id": "batch107",
            "view": 1,
            "block_id": "qc-missing",
            "block_hash": "qc-missing-h",
            "parent_id": "genesis",
            "votes": [],
        }
    )

    for i in range(7):
        assert ex.bft_cache_remote_block(
            _pending_block(
                block_id=f"child-{i}",
                parent_id=f"missing-parent-{i}",
                height=10 + i,
            )
        )

    first = ex.bft_resolved_pending_fetch_request_descriptors()
    second = ex.bft_resolved_pending_fetch_request_descriptors()
    third = ex.bft_resolved_pending_fetch_request_descriptors()

    def _missing_parent_ids(items: list[dict]) -> list[str]:
        return [
            str(item.get("block_id") or "")
            for item in items
            if str(item.get("reason") or "") == "missing_parent"
        ]

    assert [item for item in first if str(item.get("reason") or "") == "missing_qc_block"] == [
        {
            "block_id": "qc-missing",
            "block_hash": "qc-missing-h",
            "reason": "missing_qc_block",
        }
    ]
    assert len(_missing_parent_ids(first)) == 3
    assert len(_missing_parent_ids(second)) == 3
    assert len(_missing_parent_ids(third)) == 3
    assert _missing_parent_ids(first) == [
        "missing-parent-0",
        "missing-parent-1",
        "missing-parent-2",
    ]
    assert _missing_parent_ids(second) == [
        "missing-parent-3",
        "missing-parent-4",
        "missing-parent-5",
    ]
    assert _missing_parent_ids(third) == [
        "missing-parent-6",
        "missing-parent-0",
        "missing-parent-1",
    ]


def test_fetch_budget_resets_when_missing_parent_backlog_clears_batch107(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)

    for i in range(4):
        assert ex.bft_cache_remote_block(
            _pending_block(
                block_id=f"child-clear-{i}",
                parent_id=f"missing-clear-{i}",
                height=20 + i,
            )
        )

    first = ex.bft_resolved_pending_fetch_request_descriptors()
    assert [
        str(item.get("block_id") or "")
        for item in first
        if str(item.get("reason") or "") == "missing_parent"
    ] == ["missing-clear-0", "missing-clear-1", "missing-clear-2"]

    ex._pending_remote_blocks.clear()
    ex._quarantined_remote_blocks.clear()
    ex._pending_candidates.clear()

    assert ex.bft_resolved_pending_fetch_request_descriptors() == []

    assert ex.bft_cache_remote_block(
        _pending_block(block_id="child-fresh", parent_id="missing-fresh", height=50)
    )
    after_reset = ex.bft_resolved_pending_fetch_request_descriptors()
    assert after_reset == [
        {
            "block_id": "missing-fresh",
            "block_hash": "",
            "reason": "missing_parent",
            "child_block_id": "child-fresh",
        }
    ]
