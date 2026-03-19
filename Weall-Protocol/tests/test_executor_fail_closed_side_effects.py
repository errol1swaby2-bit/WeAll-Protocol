from __future__ import annotations

from pathlib import Path

import pytest

import weall.runtime.executor as executor_mod
from weall.runtime.executor import WeAllExecutor


def _mk_executor(tmp_path: Path) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="node-1",
        chain_id="weall-test",
        tx_index_path=str(Path("generated/tx_index.json")),
    )


def test_prod_build_block_candidate_fails_closed_on_poh_scheduler_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _mk_executor(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(executor_mod, "schedule_poh_tier2_system_txs", boom)

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True
    )

    assert block is None
    assert new_state is None
    assert applied_ids == []
    assert invalid_ids == []
    assert err == "poh_schedule_failed:RuntimeError"


def test_prod_build_block_candidate_fails_closed_on_system_emitter_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _mk_executor(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(executor_mod, "system_tx_emitter", boom)

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True
    )

    assert block is None
    assert new_state is None
    assert applied_ids == []
    assert invalid_ids == []
    assert err == "system_emitter_post_failed:RuntimeError"


def test_prod_apply_block_fails_closed_on_poh_scheduler_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _mk_executor(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(executor_mod, "schedule_poh_tier2_system_txs", boom)

    meta = ex.apply_block(
        {
            "header": {
                "chain_id": "weall-test",
                "height": 1,
                "prev_block_hash": "",
                "block_ts_ms": max(1, ex.chain_time_floor_ms()),
                "receipts_root": "0" * 64,
            },
            "height": 1,
            "block_ts_ms": max(1, ex.chain_time_floor_ms()),
            "txs": [],
        }
    )

    assert meta.ok is False
    assert meta.error == "bad_block:poh_schedule_failed:RuntimeError"


def test_prod_apply_block_fails_closed_on_corrupt_system_queue(tmp_path: Path) -> None:
    ex = _mk_executor(tmp_path)
    ex.state["system_queue"] = ["corrupt"]

    meta = ex.apply_block(
        {
            "header": {
                "chain_id": "weall-test",
                "height": 1,
                "prev_block_hash": "",
                "block_ts_ms": max(1, ex.chain_time_floor_ms()),
                "receipts_root": "0" * 64,
            },
            "height": 1,
            "block_ts_ms": max(1, ex.chain_time_floor_ms()),
            "txs": [],
        }
    )

    assert meta.ok is False
    assert meta.error == "bad_block:system_emitter_pre_failed:SystemQueueCorruptionError"
