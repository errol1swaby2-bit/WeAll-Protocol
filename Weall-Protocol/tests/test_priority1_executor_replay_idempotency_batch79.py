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


def _logical_state(ex: WeAllExecutor) -> dict:
    st = ex.read_state()
    return {
        "accounts": dict(st.get("accounts", {})),
        "height": int(st.get("height", 0)),
        "mempool": list(ex.read_mempool()),
    }


def test_replay_same_tx_batch79() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db = str(root / ".pytest-b79-r1.db")
    try:
        Path(db).unlink(missing_ok=True)

        ex = WeAllExecutor(db_path=db, node_id="n1", chain_id="b79", tx_index_path=tx_index_path)

        r1 = _submit_result(ex, "@a", 1)
        r2 = _submit_result(ex, "@a", 1)

        assert r1.get("ok") is True
        assert r2.get("ok") is False
        assert r2.get("error") in {"tx_id_conflict", "bad_nonce"}

        while ex.read_mempool():
            assert ex.produce_block(max_txs=10).ok is True

        state1 = _logical_state(ex)

        ex2 = WeAllExecutor(db_path=db, node_id="n1", chain_id="b79", tx_index_path=tx_index_path)

        r3 = _submit_result(ex2, "@a", 1)
        assert r3.get("ok") is False
        assert r3.get("error") in {"tx_id_conflict", "bad_nonce"}

        state2 = _logical_state(ex2)
        assert state1 == state2
    finally:
        Path(db).unlink(missing_ok=True)


def test_replay_order_independence_batch79() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(root / ".pytest-b79-r2a.db")
    db2 = str(root / ".pytest-b79-r2b.db")
    try:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)

        ex1 = WeAllExecutor(
            db_path=db1, node_id="n1", chain_id="b79o-a", tx_index_path=tx_index_path
        )
        ex2 = WeAllExecutor(
            db_path=db2, node_id="n2", chain_id="b79o-b", tx_index_path=tx_index_path
        )

        accepted = [
            ("@a", 1),
            ("@b", 1),
        ]

        for s, n in accepted:
            assert _submit_result(ex1, s, n).get("ok") is True
        assert _submit_result(ex1, "@a", 1).get("ok") is False

        assert _submit_result(ex2, "@a", 1).get("ok") is True
        assert _submit_result(ex2, "@a", 1).get("ok") is False
        assert _submit_result(ex2, "@b", 1).get("ok") is True

        while ex1.read_mempool():
            assert ex1.produce_block(max_txs=10).ok is True
        while ex2.read_mempool():
            assert ex2.produce_block(max_txs=10).ok is True

        st1 = _logical_state(ex1)
        st2 = _logical_state(ex2)

        # Block IDs may differ because node_id / chain_id can be part of block construction
        # in this implementation. The replay-safety invariant here is logical-state equivalence.
        assert st1["accounts"] == st2["accounts"]
        assert st1["height"] == st2["height"]
        assert st1["mempool"] == st2["mempool"] == []
    finally:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)
