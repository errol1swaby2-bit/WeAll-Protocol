from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_smoke_produce_10_blocks_sqlite(tmp_path: Path) -> None:
    """SQLite-backed smoke test:

    - submit 10 txs
    - produce 10 blocks (max_txs=1)
    - assert height == 10
    - assert blocks are retrievable by height
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="smoke-10", tx_index_path=tx_index_path)

    # 10 independent signers => nonce=1 each
    for i in range(10):
        sub = ex.submit_tx(
            {"tx_type": "ACCOUNT_REGISTER", "signer": f"user{i}", "nonce": 1, "payload": {"pubkey": f"k:{i}"}}
        )
        assert sub["ok"] is True

    for i in range(10):
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True
        assert meta.height == i + 1

    st = ex.read_state()
    assert int(st.get("height", 0)) == 10

    b1 = ex.get_block_by_height(1)
    b10 = ex.get_block_by_height(10)
    assert isinstance(b1, dict)
    assert isinstance(b10, dict)
    assert int(b10.get("height", 0)) == 10
