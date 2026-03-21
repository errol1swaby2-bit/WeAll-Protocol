from __future__ import annotations

from types import SimpleNamespace

from weall.runtime.executor import ExecutorMeta, WeAllExecutor


def _make_minimal_executor(
    *, pending_blocks: dict[str, dict], pending_qcs: dict[str, dict]
) -> tuple[WeAllExecutor, list[str], list[str]]:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex._pending_remote_blocks = dict(pending_blocks)
    ex._pending_candidates = {}
    ex._pending_missing_qcs = dict(pending_qcs)
    ex._bft = SimpleNamespace(finalized_block_id="")

    dropped: list[str] = []
    applied: list[str] = []

    ex._prune_pending_bft_artifacts = lambda: False
    ex._bft_phase_allows_artifact_processing = lambda: True
    ex._ordered_pending_block_ids = lambda: sorted(ex._pending_remote_blocks.keys())
    ex._has_local_block = lambda bid: False
    ex._bft_pending_block_json = lambda bid: (
        dict(ex._pending_remote_blocks[bid]) if bid in ex._pending_remote_blocks else None
    )
    ex._bft_block_is_applyable_finalized_descendant = lambda blk, finalized_block_id: True
    ex._pending_missing_qc_json = lambda *, block_id="", block_hash="": (
        dict(ex._pending_missing_qcs[block_id]) if block_id in ex._pending_missing_qcs else None
    )
    ex._block_height_hint = lambda blk: int(blk.get("height") or 0)
    ex._bft_parent_ready_for_apply = lambda blk: True

    def _drop_pending_candidate_artifacts(bid: str) -> None:
        dropped.append(str(bid))
        ex._pending_remote_blocks.pop(str(bid), None)
        ex._pending_missing_qcs.pop(str(bid), None)

    ex._drop_pending_candidate_artifacts = _drop_pending_candidate_artifacts

    def _apply_block(blk: dict) -> ExecutorMeta:
        bid = str(blk.get("block_id") or "")
        applied.append(bid)
        if bid == "B":
            return ExecutorMeta(ok=False, error="terminal-invalid", block_id=bid)
        return ExecutorMeta(ok=True, block_id=bid, height=int(blk.get("height") or 0))

    ex.apply_block = _apply_block
    return ex, dropped, applied


def test_pending_frontier_drops_terminal_apply_failure_batch99(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    block_b = {"block_id": "B", "block_hash": "hash-B", "height": 2, "prev_block_id": "A"}
    qc_b = {"block_id": "B", "block_hash": "hash-B", "view": 3}
    ex, dropped, applied = _make_minimal_executor(
        pending_blocks={"B": block_b},
        pending_qcs={"B": qc_b},
    )

    out1 = ex.bft_try_apply_pending_remote_blocks()
    out2 = ex.bft_try_apply_pending_remote_blocks()

    assert out1 == []
    assert out2 == []
    assert applied == ["B"]
    assert dropped == ["B"]
    assert ex._pending_remote_blocks == {}
    assert ex._pending_missing_qcs == {}


def test_pending_frontier_continues_after_dropping_invalid_head_batch99(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    block_b = {"block_id": "B", "block_hash": "hash-B", "height": 2, "prev_block_id": "A"}
    block_c = {"block_id": "C", "block_hash": "hash-C", "height": 3, "prev_block_id": "A"}
    qc_b = {"block_id": "B", "block_hash": "hash-B", "view": 3}
    qc_c = {"block_id": "C", "block_hash": "hash-C", "view": 4}
    ex, dropped, applied = _make_minimal_executor(
        pending_blocks={"B": block_b, "C": block_c},
        pending_qcs={"B": qc_b, "C": qc_c},
    )

    out = ex.bft_try_apply_pending_remote_blocks()

    assert applied == ["B", "C"]
    assert dropped == ["B", "C"]
    assert [m.block_id for m in out] == ["C"]
    assert ex._pending_remote_blocks == {}
    assert ex._pending_missing_qcs == {}
