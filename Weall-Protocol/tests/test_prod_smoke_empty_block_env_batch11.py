from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, *, node_id: str, chain_id: str) -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / f"{node_id.strip('@')}.db")
    return WeAllExecutor(
        db_path=db_path, node_id=node_id, chain_id=chain_id, tx_index_path=tx_index_path
    )


def test_produce_block_respects_empty_block_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_PRODUCE_EMPTY_BLOCKS", "1")

    ex = _make_executor(tmp_path, node_id="@leader", chain_id="empty-block-env")
    meta = ex.produce_block(max_txs=1000)

    assert meta.ok is True
    assert meta.error == ""
    assert int(meta.height) == 1
    assert str(meta.block_id) != ""
    assert int(meta.applied_count) == 0
    assert int(ex.read_state().get("height") or 0) == 1
