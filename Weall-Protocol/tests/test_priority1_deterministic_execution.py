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


def test_deterministic_state_across_independent_nodes_batch64(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    signers = ["@a", "@b", "@c"]

    db1 = str(tmp_path / "node1.db")
    db2 = str(tmp_path / "node2.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b64", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b64", tx_index_path=tx_index_path)

    # same txs, same order
    for s in signers:
        _submit(ex1, s, 1)
        _submit(ex2, s, 1)

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=1).ok is True
    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=1).ok is True

    st1 = ex1.read_state()
    st2 = ex2.read_state()

    assert st1.get("accounts") == st2.get("accounts")
    assert int(st1.get("height", 0)) == int(st2.get("height", 0))


def test_different_batching_same_result_batch64(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    signers = ["@d", "@e", "@f", "@g"]

    db1 = str(tmp_path / "small.db")
    db2 = str(tmp_path / "large.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b64a", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b64b", tx_index_path=tx_index_path)

    for s in signers:
        _submit(ex1, s, 1)
        _submit(ex2, s, 1)

    # different batching strategies
    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=1).ok is True

    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=10).ok is True

    st1 = ex1.read_state()
    st2 = ex2.read_state()

    for s in signers:
        assert s in st1.get("accounts", {})
        assert s in st2.get("accounts", {})

    assert len(st1.get("accounts", {})) == len(st2.get("accounts", {}))


def test_transaction_order_determinism_batch64(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(tmp_path / "order1.db")
    db2 = str(tmp_path / "order2.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b64c", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b64c", tx_index_path=tx_index_path)

    # same logical tx set, different submission order
    _submit(ex1, "@x", 1)
    _submit(ex1, "@y", 1)

    _submit(ex2, "@y", 1)
    _submit(ex2, "@x", 1)

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=10).ok is True
    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=10).ok is True

    st1 = ex1.read_state()
    st2 = ex2.read_state()

    # final state must match regardless of submission order
    assert st1.get("accounts") == st2.get("accounts")
