from __future__ import annotations

from pathlib import Path
from types import MethodType

import pytest

from weall.runtime.executor import ExecutorMeta, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, name: str, *, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def test_pending_frontier_replay_attaches_cached_qc_as_justify_qc_batch98(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _executor(tmp_path, "node-a", chain_id="batch98-a")

    bid = "B"
    block = {
        "block_id": bid,
        "block_hash": "B-h",
        "prev_block_id": "A",
        "height": 2,
        "header": {"chain_id": "batch98-a", "height": 2, "block_ts_ms": 2},
        "txs": [],
    }
    qcj = {
        "chain_id": "batch98-a",
        "view": 7,
        "block_id": bid,
        "block_hash": "B-h",
        "parent_id": "A",
        "votes": [],
    }

    ex.state["tip"] = "A"
    ex.state["height"] = 1
    ex._pending_remote_blocks[bid] = dict(block)
    ex._index_pending_remote_block(block)
    ex._put_pending_missing_qc(qcj)

    seen: list[dict[str, object]] = []

    def _fake_apply_block(self: WeAllExecutor, blk: dict[str, object]) -> ExecutorMeta:
        seen.append(dict(blk))
        return ExecutorMeta(ok=True, height=2, block_id=bid)

    ex.apply_block = MethodType(_fake_apply_block, ex)

    metas = ex.bft_try_apply_pending_remote_blocks()

    assert len(metas) == 1
    assert len(seen) == 1
    assert isinstance(seen[0].get("justify_qc"), dict)
    assert seen[0]["justify_qc"]["block_id"] == bid
    assert "qc" not in seen[0]


def test_pending_frontier_drops_conflicting_cached_qc_when_block_already_has_justify_qc_batch98(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _executor(tmp_path, "node-b", chain_id="batch98-b")

    bid = "B"
    block = {
        "block_id": bid,
        "block_hash": "B-h",
        "prev_block_id": "A",
        "height": 2,
        "justify_qc": {
            "chain_id": "batch98-b",
            "view": 5,
            "block_id": "A",
            "block_hash": "A-h",
            "parent_id": "genesis",
            "votes": [],
        },
        "header": {"chain_id": "batch98-b", "height": 2, "block_ts_ms": 2},
        "txs": [],
    }
    conflicting_qcj = {
        "chain_id": "batch98-b",
        "view": 7,
        "block_id": bid,
        "block_hash": "B-h",
        "parent_id": "A",
        "votes": [],
    }

    ex.state["tip"] = "A"
    ex.state["height"] = 1
    ex._pending_remote_blocks[bid] = dict(block)
    ex._index_pending_remote_block(block)
    ex._put_pending_missing_qc(conflicting_qcj)

    called = {"apply": 0}

    def _fake_apply_block(self: WeAllExecutor, blk: dict[str, object]) -> ExecutorMeta:
        called["apply"] += 1
        return ExecutorMeta(ok=True, height=2, block_id=bid)

    ex.apply_block = MethodType(_fake_apply_block, ex)

    metas = ex.bft_try_apply_pending_remote_blocks()

    assert metas == []
    assert called["apply"] == 0
    assert bid not in ex._pending_remote_blocks
    assert ex._pending_missing_qc_json(block_id=bid) is None
