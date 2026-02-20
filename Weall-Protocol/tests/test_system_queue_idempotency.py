from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_produce_block_is_idempotent_when_mempool_empty(tmp_path: Path) -> None:
    """If no txs are in the mempool, produce_block() must not advance height."""
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="empty-mempool", tx_index_path=tx_index_path)
    st0 = ex.read_state()
    h0 = int(st0.get("height", 0))

    meta = ex.produce_block(max_txs=1000)
    assert meta.ok is True
    assert meta.height == h0  # no txs applied, height stays put

    st1 = ex.read_state()
    assert int(st1.get("height", 0)) == h0
