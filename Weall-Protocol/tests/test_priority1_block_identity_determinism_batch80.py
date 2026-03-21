from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _submit(ex: WeAllExecutor, signer: str, nonce: int) -> dict:
    return ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}:{nonce}"},
        }
    )


def _latest_block_id(ex: WeAllExecutor) -> str:
    latest = ex.get_latest_block()
    if not isinstance(latest, dict):
        return ""
    return str(latest.get("block_id") or "")


def test_same_node_same_inputs_stable_block_identity_across_restart_batch80() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(root / ".pytest-b80-a.db")
    db2 = str(root / ".pytest-b80-b.db")
    try:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)

        ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b80", tx_index_path=tx_index_path)
        ex2 = WeAllExecutor(db_path=db2, node_id="n1", chain_id="b80", tx_index_path=tx_index_path)

        for signer in ["@a", "@b"]:
            assert _submit(ex1, signer, 1).get("ok") is True
            assert _submit(ex2, signer, 1).get("ok") is True

        assert ex1.produce_block(max_txs=10).ok is True
        assert ex2.produce_block(max_txs=10).ok is True

        assert _latest_block_id(ex1) == _latest_block_id(ex2)
    finally:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)


def test_same_node_chunking_keeps_same_logical_result_batch80() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(root / ".pytest-b80-c.db")
    db2 = str(root / ".pytest-b80-d.db")
    try:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)

        ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b80c", tx_index_path=tx_index_path)
        ex2 = WeAllExecutor(db_path=db2, node_id="n1", chain_id="b80c", tx_index_path=tx_index_path)

        for signer in ["@c", "@d", "@e"]:
            assert _submit(ex1, signer, 1).get("ok") is True
            assert _submit(ex2, signer, 1).get("ok") is True

        while ex1.read_mempool():
            assert ex1.produce_block(max_txs=1).ok is True
        while ex2.read_mempool():
            assert ex2.produce_block(max_txs=10).ok is True

        st1 = ex1.read_state()
        st2 = ex2.read_state()

        # Chunking may change the number of blocks / height, but not the logical committed result.
        assert st1.get("accounts") == st2.get("accounts")
        assert len(st1.get("accounts", {})) == 3
        assert len(st2.get("accounts", {})) == 3
        assert len(ex1.read_mempool()) == 0
        assert len(ex2.read_mempool()) == 0
    finally:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)


def test_restart_before_production_does_not_change_first_block_identity_batch80() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(root / ".pytest-b80-e.db")
    db2 = str(root / ".pytest-b80-f.db")
    try:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)

        ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b80r", tx_index_path=tx_index_path)
        ex2 = WeAllExecutor(db_path=db2, node_id="n1", chain_id="b80r", tx_index_path=tx_index_path)

        for signer in ["@x", "@y"]:
            assert _submit(ex1, signer, 1).get("ok") is True
            assert _submit(ex2, signer, 1).get("ok") is True

        ex2 = WeAllExecutor(db_path=db2, node_id="n1", chain_id="b80r", tx_index_path=tx_index_path)

        assert ex1.produce_block(max_txs=10).ok is True
        assert ex2.produce_block(max_txs=10).ok is True

        assert _latest_block_id(ex1) == _latest_block_id(ex2)
    finally:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)


def test_different_chain_ids_may_change_block_identity_without_state_divergence_batch80() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(root / ".pytest-b80-g.db")
    db2 = str(root / ".pytest-b80-h.db")
    try:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)

        ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b80g1", tx_index_path=tx_index_path)
        ex2 = WeAllExecutor(db_path=db2, node_id="n1", chain_id="b80g2", tx_index_path=tx_index_path)

        for signer in ["@m", "@n"]:
            assert _submit(ex1, signer, 1).get("ok") is True
            assert _submit(ex2, signer, 1).get("ok") is True

        assert ex1.produce_block(max_txs=10).ok is True
        assert ex2.produce_block(max_txs=10).ok is True

        st1 = ex1.read_state()
        st2 = ex2.read_state()

        assert st1.get("accounts") == st2.get("accounts")
        assert int(st1.get("height", 0)) == int(st2.get("height", 0))
    finally:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)
