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


def _state_accounts(ex: WeAllExecutor) -> dict:
    return dict(ex.read_state().get("accounts", {}))


def test_same_logical_work_replayed_in_multiple_chunks_matches_single_chunk_batch70(
    tmp_path: Path,
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    signers = ["@a", "@b", "@c", "@d", "@e"]

    db_single = str(tmp_path / "single.db")
    ex_single = WeAllExecutor(
        db_path=db_single,
        node_id="n1",
        chain_id="b70-single",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        assert _submit(ex_single, signer, 1).get("ok") is True
    while ex_single.read_mempool():
        assert ex_single.produce_block(max_txs=10).ok is True
    accounts_single = _state_accounts(ex_single)

    db_chunked = str(tmp_path / "chunked.db")
    ex_chunked = WeAllExecutor(
        db_path=db_chunked,
        node_id="n1",
        chain_id="b70-chunked",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        assert _submit(ex_chunked, signer, 1).get("ok") is True
    while ex_chunked.read_mempool():
        assert ex_chunked.produce_block(max_txs=2).ok is True
    accounts_chunked = _state_accounts(ex_chunked)

    assert accounts_single == accounts_chunked


def test_restart_between_each_commit_matches_continuous_execution_batch70(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    signers = ["@f", "@g", "@h", "@i"]

    db_cont = str(tmp_path / "cont.db")
    ex_cont = WeAllExecutor(
        db_path=db_cont,
        node_id="n2",
        chain_id="b70-cont",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        assert _submit(ex_cont, signer, 1).get("ok") is True
    while ex_cont.read_mempool():
        assert ex_cont.produce_block(max_txs=1).ok is True
    accounts_cont = _state_accounts(ex_cont)

    db_restart = str(tmp_path / "restart.db")
    ex_restart = WeAllExecutor(
        db_path=db_restart,
        node_id="n2",
        chain_id="b70-restart",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        assert _submit(ex_restart, signer, 1).get("ok") is True
    while ex_restart.read_mempool():
        assert ex_restart.produce_block(max_txs=1).ok is True
        ex_restart = WeAllExecutor(
            db_path=db_restart,
            node_id="n2",
            chain_id="b70-restart",
            tx_index_path=tx_index_path,
        )
    accounts_restart = _state_accounts(ex_restart)

    assert accounts_cont == accounts_restart


def test_rejected_replay_attempts_do_not_change_final_state_batch70(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "replay.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="n3",
        chain_id="b70-replay",
        tx_index_path=tx_index_path,
    )
    for signer in ["@j", "@k"]:
        assert _submit(ex, signer, 1).get("ok") is True
    while ex.read_mempool():
        assert ex.produce_block(max_txs=10).ok is True

    state_before = ex.read_state()

    for signer in ["@j", "@k"]:
        res = _submit(ex, signer, 1)
        assert res.get("ok") is False

    assert ex.produce_block(max_txs=10).ok is True
    state_after = ex.read_state()

    assert state_before == state_after


def test_interleaved_valid_and_rejected_work_converges_consistently_batch70(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db1 = str(tmp_path / "n1.db")
    db2 = str(tmp_path / "n2.db")

    ex1 = WeAllExecutor(db_path=db1, node_id="n4", chain_id="b70-a", tx_index_path=tx_index_path)
    ex2 = WeAllExecutor(db_path=db2, node_id="n4", chain_id="b70-b", tx_index_path=tx_index_path)

    # node 1 sees valid then rejected
    assert _submit(ex1, "@x", 1).get("ok") is True
    assert _submit(ex1, "@x", 1).get("ok") is False
    assert _submit(ex1, "@y", 1).get("ok") is True

    # node 2 sees rejected then valid
    assert _submit(ex2, "@x", 2).get("ok") is False
    assert _submit(ex2, "@x", 1).get("ok") is True
    assert _submit(ex2, "@y", 1).get("ok") is True

    while ex1.read_mempool():
        assert ex1.produce_block(max_txs=10).ok is True
    while ex2.read_mempool():
        assert ex2.produce_block(max_txs=10).ok is True

    assert _state_accounts(ex1) == _state_accounts(ex2)
