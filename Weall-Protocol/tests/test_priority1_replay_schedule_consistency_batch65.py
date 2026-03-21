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


def _latest_block_id(ex: WeAllExecutor) -> str:
    latest = ex.get_latest_block()
    if not isinstance(latest, dict):
        return ""
    return str(latest.get("block_id") or "")


def test_replay_same_committed_history_on_fresh_node_batch65(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    signers = ["@a", "@b", "@c"]

    db1 = str(tmp_path / "node1.db")
    ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b65a", tx_index_path=tx_index_path)
    for s in signers:
        _submit(ex1, s, 1)

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=1).ok is True

    state1 = ex1.read_state()
    tip1 = _latest_block_id(ex1)
    height1 = int(state1.get("height", 0))

    db2 = str(tmp_path / "node2.db")
    ex2 = WeAllExecutor(db_path=db2, node_id="n2", chain_id="b65b", tx_index_path=tx_index_path)
    for s in signers:
        _submit(ex2, s, 1)

    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=1).ok is True

    state2 = ex2.read_state()
    tip2 = _latest_block_id(ex2)
    height2 = int(state2.get("height", 0))

    assert state1.get("accounts") == state2.get("accounts")
    assert height1 == height2
    assert bool(tip1) == bool(tip2)


def test_restart_mid_schedule_and_resume_keeps_same_final_accounts_batch65(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    signers = ["@d", "@e", "@f", "@g"]

    db_path = str(tmp_path / "resume.db")
    ex = WeAllExecutor(db_path=db_path, node_id="n3", chain_id="b65c", tx_index_path=tx_index_path)

    for s in signers:
        _submit(ex, s, 1)

    assert ex.produce_block(max_txs=2).ok is True
    partial_height = int(ex.read_state().get("height", 0))
    assert partial_height >= 1

    ex = WeAllExecutor(db_path=db_path, node_id="n3", chain_id="b65c", tx_index_path=tx_index_path)
    while ex.read_mempool():
        assert ex.produce_block(max_txs=2).ok is True

    state = ex.read_state()
    for s in signers:
        assert s in state.get("accounts", {})

    assert len(ex.read_mempool()) == 0
    assert int(state.get("height", 0)) >= partial_height


def test_same_transactions_with_restart_vs_no_restart_same_result_batch65(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    signers = ["@h", "@i", "@j"]

    db_a = str(tmp_path / "norestart.db")
    ex_a = WeAllExecutor(db_path=db_a, node_id="n4", chain_id="b65d", tx_index_path=tx_index_path)
    for s in signers:
        _submit(ex_a, s, 1)
    while ex_a.read_mempool():
        assert ex_a.produce_block(max_txs=10).ok is True
    state_a = ex_a.read_state()

    db_b = str(tmp_path / "withrestart.db")
    ex_b = WeAllExecutor(db_path=db_b, node_id="n4", chain_id="b65e", tx_index_path=tx_index_path)
    for s in signers:
        _submit(ex_b, s, 1)
    assert ex_b.produce_block(max_txs=1).ok is True
    ex_b = WeAllExecutor(db_path=db_b, node_id="n4", chain_id="b65e", tx_index_path=tx_index_path)
    while ex_b.read_mempool():
        assert ex_b.produce_block(max_txs=10).ok is True
    state_b = ex_b.read_state()

    assert state_a.get("accounts") == state_b.get("accounts")


def test_empty_restart_cycles_do_not_change_committed_state_batch65(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "emptycycles.db")
    ex = WeAllExecutor(db_path=db_path, node_id="n5", chain_id="b65f", tx_index_path=tx_index_path)
    _submit(ex, "@k", 1)
    assert ex.produce_block(max_txs=10).ok is True

    expected_accounts = ex.read_state().get("accounts", {})
    expected_height = int(ex.read_state().get("height", 0))
    expected_tip = _latest_block_id(ex)

    for _ in range(4):
        ex = WeAllExecutor(db_path=db_path, node_id="n5", chain_id="b65f", tx_index_path=tx_index_path)
        assert len(ex.read_mempool()) == 0
        assert ex.produce_block(max_txs=10).ok is True
        assert ex.read_state().get("accounts", {}) == expected_accounts
        assert int(ex.read_state().get("height", 0)) == expected_height
        assert _latest_block_id(ex) == expected_tip
