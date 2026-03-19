# tests/test_executor_atomic_commit_crash_recovery.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_executor_atomic_commit_rolls_back_on_mid_commit_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Production invariant: block insert + mempool cleanup + snapshot must be atomic.

    We simulate a failure after inserting the block row but before writing
    the ledger_state snapshot. With atomic commit, *nothing* from the commit
    should be persisted.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="crash-test", tx_index_path=tx_index_path
    )

    # Put at least one tx in the mempool so the candidate is non-empty.
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user0",
            "nonce": 1,
            "payload": {"pubkey": "k:0"},
        }
    )
    assert sub["ok"] is True

    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
    assert err == ""

    # Fail after block insert, before writing snapshot.
    monkeypatch.setenv("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", "1")
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    assert meta.ok is False

    # On restart, there should be no blocks and height==0, and mempool still has the tx.
    ex2 = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="crash-test", tx_index_path=tx_index_path
    )
    st = ex2.read_state()
    assert int(st.get("height", 0)) == 0

    mp = ex2.read_mempool()
    assert len(mp) == 1
