from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_restart_loop_produces_append_only_blocks(tmp_path: Path) -> None:
    """Old finalize-loop test replaced with restart+loop persistence smoke."""
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="loop", tx_index_path=tx_index_path)

    for i in range(3):
        assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": f"u{i}", "nonce": 1, "payload": {}})["ok"] is True
        assert ex.produce_block(max_txs=1).ok is True

    ex2 = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="loop", tx_index_path=tx_index_path)
    assert int(ex2.read_state().get("height", 0)) == 3

    # Produce one more block after restart
    assert ex2.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "u3", "nonce": 1, "payload": {}})["ok"] is True
    meta = ex2.produce_block(max_txs=1)
    assert meta.ok is True
    assert meta.height == 4

    b4 = ex2.get_block_by_height(4)
    assert isinstance(b4, dict)
    assert int(b4.get("height", 0)) == 4
