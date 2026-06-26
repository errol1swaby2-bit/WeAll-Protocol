from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _submit(ex: WeAllExecutor, signer: str, nonce: int) -> None:
    res = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}:{nonce}"},
        }
    )
    assert res.get("ok") is True


def test_parallel_submission_order_independence_batch55(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "parallel.db")

    ex = WeAllExecutor(db_path=db_path, node_id="v1", chain_id="b55", tx_index_path=tx_index_path)

    # simulate unordered arrival
    _submit(ex, "@a", 1)
    _submit(ex, "@c", 1)
    _submit(ex, "@b", 1)

    while ex.read_mempool():
        meta = ex.produce_block(max_txs=2)
        assert meta.ok is True

    st = ex.read_state()
    assert "@a" in st.get("accounts", {})
    assert "@b" in st.get("accounts", {})
    assert "@c" in st.get("accounts", {})


def test_large_mempool_chunking_consistency_batch55(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "chunk.db")

    ex = WeAllExecutor(db_path=db_path, node_id="v2", chain_id="b55", tx_index_path=tx_index_path)

    for i in range(20):
        _submit(ex, f"@user{i}", 1)

    # produce in small chunks
    while ex.read_mempool():
        meta = ex.produce_block(max_txs=3)
        assert meta.ok is True

    st = ex.read_state()
    for i in range(20):
        assert f"@user{i}" in st.get("accounts", {})


def test_mempool_deterministic_iteration_order_batch55(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "order.db")

    ex1 = WeAllExecutor(db_path=db_path, node_id="v3", chain_id="b55", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db_path, node_id="v3", chain_id="b55", tx_index_path=tx_index_path)

    for signer in ["@x", "@y", "@z"]:
        _submit(ex1, signer, 1)

    mp1 = list(ex1.read_mempool())

    ex2 = WeAllExecutor(db_path=db_path, node_id="v3", chain_id="b55", tx_index_path=tx_index_path)
    mp2 = list(ex2.read_mempool())

    assert mp1 == mp2


def test_repeated_block_production_does_not_skip_tx_batch55(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "skip.db")

    ex = WeAllExecutor(db_path=db_path, node_id="v4", chain_id="b55", tx_index_path=tx_index_path)

    for i in range(5):
        _submit(ex, f"@u{i}", 1)

    seen = set()

    while ex.read_mempool():
        mp_before = list(ex.read_mempool())
        meta = ex.produce_block(max_txs=2)
        assert meta.ok is True

        st = ex.read_state()
        seen.update(st.get("accounts", {}).keys())

        mp_after = list(ex.read_mempool())
        assert len(mp_after) <= len(mp_before)

    assert len(seen) >= 5
