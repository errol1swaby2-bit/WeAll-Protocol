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


def test_missing_parent_fetch_requests_are_bounded_and_rotating(
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
        block = _pending_block(
            block_id=f"child-{i}",
            parent_id=f"missing-parent-{i}",
            height=10 + i,
        )
        ex._put_pending_remote_block(block_id=str(block["block_id"]), block=block)

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


def test_fetch_budget_resets_when_missing_parent_backlog_clears(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)

    for i in range(4):
        block = _pending_block(
            block_id=f"child-clear-{i}",
            parent_id=f"missing-clear-{i}",
            height=20 + i,
        )
        ex._put_pending_remote_block(block_id=str(block["block_id"]), block=block)

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

    block = _pending_block(block_id="child-fresh", parent_id="missing-fresh", height=50)
    ex._put_pending_remote_block(block_id=str(block["block_id"]), block=block)
    after_reset = ex.bft_resolved_pending_fetch_request_descriptors()
    assert after_reset == [
        {
            "block_id": "missing-fresh",
            "block_hash": "",
            "reason": "missing_parent",
            "child_block_id": "child-fresh",
        }
    ]


def test_finalized_frontier_keeps_unknown_hash_bound_qc_and_missing_parent(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)
    ex.state["height"] = 3
    ex.state["tip"] = "C1"
    ex.state["blocks"] = {
        "A": {"prev_block_id": "", "height": 1, "block_hash": "A-h"},
        "B1": {"prev_block_id": "A", "height": 2, "block_hash": "B1-h"},
        "C1": {"prev_block_id": "B1", "height": 3, "block_hash": "C1-h"},
    }
    ex._bft.finalized_block_id = "C1"
    # Simulate artifacts which have already crossed authenticated admission.
    # No unverified QC is admitted by this test; this covers pruning only.
    ex._put_pending_missing_qc({
        "t": "QC", "chain_id": "batch107", "view": 5,
        "block_id": "FUTURE", "block_hash": "FUTURE-h",
        "parent_id": "MISSING", "votes": [],
    })
    child = _pending_block(block_id="FUTURE-CHILD", parent_id="MISSING", height=6)
    ex._put_pending_remote_block(block_id="FUTURE-CHILD", block=child)
    assert ex._prune_pending_bft_artifacts() is False
    assert "FUTURE" in ex._pending_missing_qcs
    assert "FUTURE-CHILD" in ex._pending_remote_blocks
    descriptors = ex.bft_resolved_pending_fetch_request_descriptors()
    assert {
        "block_id": "FUTURE",
        "block_hash": "FUTURE-h",
        "reason": "missing_qc_block",
    } in descriptors
    assert any(
        item["block_id"] == "MISSING" and item["reason"] == "missing_parent"
        for item in descriptors
    )


def test_finalized_frontier_prunes_known_fork_and_ancestry_cycle(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)
    ex.state["height"] = 3
    ex.state["tip"] = "C1"
    ex.state["blocks"] = {
        "A": {"prev_block_id": "", "height": 1, "block_hash": "A-h"},
        "B1": {"prev_block_id": "A", "height": 2, "block_hash": "B1-h"},
        "C1": {"prev_block_id": "B1", "height": 3, "block_hash": "C1-h"},
        "B2": {"prev_block_id": "A", "height": 2, "block_hash": "B2-h"},
        "C2": {"prev_block_id": "B2", "height": 3, "block_hash": "C2-h"},
    }
    ex._bft.finalized_block_id = "C1"
    ex._put_pending_missing_qc({
        "t": "QC", "chain_id": "batch107", "view": 5,
        "block_id": "D2", "block_hash": "D2-h",
        "parent_id": "C2", "votes": [],
    })
    ex._put_pending_remote_block(
        block_id="D2",
        block=_pending_block(block_id="D2", parent_id="C2", height=4),
    )
    ex._put_pending_remote_block(
        block_id="CYCLE",
        block=_pending_block(block_id="CYCLE", parent_id="CYCLE", height=5),
    )
    assert ex._prune_pending_bft_artifacts() is True
    assert "D2" not in ex._pending_missing_qcs
    assert "D2" not in ex._pending_remote_blocks
    assert "CYCLE" not in ex._pending_remote_blocks
