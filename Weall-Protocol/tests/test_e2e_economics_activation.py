from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_blocks_are_append_only_and_height_monotonic(tmp_path: Path) -> None:
    """Economics activation is handled elsewhere; for SQLite migration we preserve the core chain invariant."""
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="monotonic", tx_index_path=tx_index_path)

    for i in range(5):
        assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": f"u{i}", "nonce": 1, "payload": {}})["ok"] is True
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True
        assert meta.height == i + 1

    # Ensure blocks exist for each height.
    for h in range(1, 6):
        blk = ex.get_block_by_height(h)
        assert isinstance(blk, dict)
        assert int(blk.get("height", 0)) == h
