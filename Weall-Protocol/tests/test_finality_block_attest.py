from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_block_retrieval_and_tip_persistence(tmp_path: Path) -> None:
    """Replaces the old finality/attestation test with a persistence invariant:

    - blocks must be retrievable by height
    - tip must survive restarts
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="blocks", tx_index_path=tx_index_path)

    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "u1", "nonce": 1, "payload": {}})["ok"] is True
    m1 = ex.produce_block(max_txs=1)
    assert m1.ok is True
    assert m1.height == 1

    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "u2", "nonce": 1, "payload": {}})["ok"] is True
    m2 = ex.produce_block(max_txs=1)
    assert m2.ok is True
    assert m2.height == 2

    b2 = ex.get_block_by_height(2)
    assert isinstance(b2, dict)
    assert str(b2.get("block_id") or "")

    # Restart and ensure tip/height persist.
    ex2 = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="blocks", tx_index_path=tx_index_path)
    st = ex2.read_state()
    assert int(st.get("height", 0)) == 2
    assert str(st.get("tip") or "").strip()
