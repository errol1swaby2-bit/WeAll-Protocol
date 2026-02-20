from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_restart_does_not_duplicate_blocks(tmp_path: Path) -> None:
    """SQLite persistence smoke:

    - submit 2 txs and produce 2 blocks
    - restart executor pointing at same db
    - submit 1 more tx and produce 1 more block
    - ensure heights persist and blocks are append-only
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="restart-smoke", tx_index_path=tx_index_path)

    # Force one tx per block.
    for i in range(2):
        sub = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": f"user{i}", "nonce": 1, "payload": {"pubkey": f"k:{i}"}})
        assert sub["ok"] is True
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True
        assert meta.height == i + 1

    b1 = ex.get_block_by_height(1)
    b2 = ex.get_block_by_height(2)
    assert isinstance(b1, dict)
    assert isinstance(b2, dict)

    # Restart against same DB
    ex2 = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="restart-smoke", tx_index_path=tx_index_path)
    st = ex2.read_state()
    assert int(st.get("height", 0)) == 2

    # Produce one more block
    sub3 = ex2.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "user2", "nonce": 1, "payload": {"pubkey": "k:2"}})
    assert sub3["ok"] is True
    meta3 = ex2.produce_block(max_txs=1)
    assert meta3.ok is True
    assert meta3.height == 3

    b3 = ex2.get_block_by_height(3)
    assert isinstance(b3, dict)
    assert int(b3.get("height", 0)) == 3
