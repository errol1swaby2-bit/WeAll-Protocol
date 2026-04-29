from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _submit_result(ex: WeAllExecutor, signer: str, nonce: int) -> dict:
    return ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}:{nonce}"},
        }
    )


def _state_snapshot(ex: WeAllExecutor) -> dict:
    st = ex.read_state()
    return {
        "accounts": dict(st.get("accounts", {})),
        "height": int(st.get("height", 0)),
    }


def test_concurrent_like_submission_order_independence_batch66(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(tmp_path / "n1.db")
    db2 = str(tmp_path / "n2.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b66", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b66", tx_index_path=tx_index_path)

    for signer in ["@a", "@b", "@c"]:
        assert _submit_result(ex1, signer, 1).get("ok") is True

    for signer in ["@a", "@c", "@b"]:
        assert _submit_result(ex2, signer, 1).get("ok") is True

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=2).ok is True
    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=2).ok is True

    assert _state_snapshot(ex1) == _state_snapshot(ex2)


def test_duplicate_submission_handling_is_deterministic_batch66(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(tmp_path / "dup1.db")
    db2 = str(tmp_path / "dup2.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b66d", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b66d", tx_index_path=tx_index_path)

    r11 = _submit_result(ex1, "@x", 1)
    r12 = _submit_result(ex1, "@x", 1)

    r21 = _submit_result(ex2, "@x", 1)

    assert r11.get("ok") is True
    assert r12.get("ok") is False
    assert r12.get("error") == "tx_id_conflict"
    assert r21.get("ok") is True

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=10).ok is True
    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=10).ok is True

    st1 = ex1.read_state()
    st2 = ex2.read_state()

    assert st1.get("accounts") == st2.get("accounts")


def test_nonce_conflict_resolution_is_consistent_batch66(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(tmp_path / "nonce1.db")
    db2 = str(tmp_path / "nonce2.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b66n", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b66n", tx_index_path=tx_index_path)

    r11 = _submit_result(ex1, "@z", 1)
    r12 = _submit_result(ex1, "@z", 2)

    r21 = _submit_result(ex2, "@z", 2)
    r22 = _submit_result(ex2, "@z", 1)

    assert r11.get("ok") is True
    assert r12.get("ok") is False
    assert r12.get("error") == "bad_nonce"

    assert r21.get("ok") is False
    assert r21.get("error") == "bad_nonce"
    assert r22.get("ok") is True

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=10).ok is True
    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=10).ok is True

    st1 = ex1.read_state()
    st2 = ex2.read_state()

    assert st1.get("accounts") == st2.get("accounts")
