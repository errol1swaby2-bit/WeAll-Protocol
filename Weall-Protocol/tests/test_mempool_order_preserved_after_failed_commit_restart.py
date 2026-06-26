from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_mempool_order_preserved_after_failed_commit_restart_batch41(tmp_path: Path, monkeypatch) -> None:
    """
    New coverage: after a rollback triggered during block commit, all selected txs
    must remain pending *and* preserve their FIFO order across restart.

    This is intentionally different from earlier single-tx rollback tests.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="batch41-mempool-order-after-failed-commit",
        tx_index_path=tx_index_path,
    )

    submitted: list[str] = []
    for idx in range(3):
        sub = ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": f"@user{idx}",
                "nonce": 1,
                "payload": {"pubkey": f"k:{idx}"},
            }
        )
        assert sub["ok"] is True
        submitted.append(str(sub["tx_id"]))

    before = [str(item["tx_id"]) for item in ex.read_mempool()]
    assert before == submitted

    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=3, allow_empty=False)
    assert err == ""
    assert applied_ids == submitted
    assert invalid_ids == []

    monkeypatch.setenv("WEALL_TEST_FAILPOINTS", "block_commit_after_ledger_state")
    meta = ex.commit_block_candidate(
        block=blk,
        new_state=st2,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is False
    monkeypatch.delenv("WEALL_TEST_FAILPOINTS", raising=False)

    same_process = [str(item["tx_id"]) for item in ex.read_mempool()]
    assert same_process == submitted
    assert int(ex.read_state().get("height", 0)) == 0

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="batch41-mempool-order-after-failed-commit",
        tx_index_path=tx_index_path,
    )
    after_restart = [str(item["tx_id"]) for item in ex2.read_mempool()]
    assert after_restart == submitted
    assert int(ex2.read_state().get("height", 0)) == 0
