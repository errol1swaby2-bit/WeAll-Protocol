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


def test_cross_node_restart_and_merge_consistency_batch69(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(tmp_path / "n1.db")
    db2 = str(tmp_path / "n2.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b69", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b69", tx_index_path=tx_index_path)

    # split work across nodes
    assert _submit(ex1, "@a", 1).get("ok") is True
    assert _submit(ex2, "@b", 1).get("ok") is True

    assert ex1.produce_block(max_txs=10).ok is True
    assert ex2.produce_block(max_txs=10).ok is True

    # restart both
    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b69", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b69", tx_index_path=tx_index_path)

    # continue with same logical set
    assert _submit(ex1, "@b", 1).get("ok") is True
    assert _submit(ex2, "@a", 1).get("ok") is True

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=10).ok is True
    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=10).ok is True

    st1 = ex1.read_state()
    st2 = ex2.read_state()

    assert st1.get("accounts") == st2.get("accounts")


def test_redundant_replay_after_full_commit_is_noop_batch69(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "noop.db")

    ex = WeAllExecutor(db_path=db_path, node_id="n3", chain_id="b69-noop", tx_index_path=tx_index_path)

    for signer in ["@c", "@d"]:
        assert _submit(ex, signer, 1).get("ok") is True

    while ex.read_mempool():
        assert ex.produce_block(max_txs=10).ok is True

    state_before = ex.read_state()

    # replay same logical txs (should be rejected / no-op)
    for signer in ["@c", "@d"]:
        res = _submit(ex, signer, 1)
        assert res.get("ok") is False

    assert ex.produce_block(max_txs=10).ok is True
    state_after = ex.read_state()

    assert state_before == state_after


def test_interleaved_restart_and_submission_does_not_create_duplicates_batch69(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "dupguard.db")

    ex = WeAllExecutor(db_path=db_path, node_id="n4", chain_id="b69-dup", tx_index_path=tx_index_path)

    assert _submit(ex, "@x", 1).get("ok") is True

    ex = WeAllExecutor(db_path=db_path, node_id="n4", chain_id="b69-dup", tx_index_path=tx_index_path)

    # try duplicate after restart
    res = _submit(ex, "@x", 1)
    assert res.get("ok") is False

    while ex.read_mempool():
        assert ex.produce_block(max_txs=10).ok is True

    st = ex.read_state()
    keys = st.get("accounts", {}).get("@x", {}).get("keys", {}).get("by_id", {})
    assert len(keys) == 1
