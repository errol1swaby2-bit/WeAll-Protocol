from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


class _ConnProxy:
    """Proxy a sqlite connection and optionally fail on matching SQL.

    We use this to simulate a crash/exception *mid-commit* while still
    running in-process (pytest cannot hard-kill the interpreter safely).
    """

    def __init__(self, con: Any, *, fail_sql_contains: str) -> None:
        self._con = con
        self._needle = str(fail_sql_contains)

    def execute(self, sql: str, *args: Any, **kwargs: Any):
        if self._needle and self._needle in str(sql):
            raise RuntimeError("simulated_crash_during_commit")
        return self._con.execute(sql, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._con, name)


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

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="crash-test", tx_index_path=tx_index_path)

    # Put at least one tx in the mempool so the candidate is non-empty.
    sub = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "user0", "nonce": 1, "payload": {"pubkey": "k:0"}})
    assert sub["ok"] is True

    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
    assert err == ""
    assert blk is not None
    assert st2 is not None
    assert len(applied_ids) >= 1

    # Patch write_tx so the yielded connection raises during the ledger_state upsert.
    orig_write_tx = ex._db.write_tx

    @contextmanager
    def _crashy_write_tx() -> Iterator[Any]:
        with orig_write_tx() as con:
            yield _ConnProxy(con, fail_sql_contains="ledger_state")

    monkeypatch.setattr(ex._db, "write_tx", _crashy_write_tx)

    meta = ex.commit_block_candidate(block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)
    assert meta.ok is False
    assert meta.error.startswith("commit_failed")

    # Nothing should have been committed:
    # - height remains 0
    # - no blocks persisted
    # - mempool item remains
    ex2 = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="crash-test", tx_index_path=tx_index_path)
    assert int(ex2.read_state().get("height", 0)) == 0
    assert ex2.get_latest_block() is None

    pending = ex2.mempool.peek(limit=10)
    assert isinstance(pending, list)
    assert len(pending) >= 1
