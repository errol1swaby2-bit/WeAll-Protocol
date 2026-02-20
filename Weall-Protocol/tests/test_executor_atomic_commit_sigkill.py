from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_executor_atomic_commit_survives_sigkill_mid_commit(tmp_path: Path) -> None:
    """Crash-hardening: SIGKILL during commit must not partially persist DB.

    We run a subprocess that:
      - creates an executor
      - submits a tx
      - builds a candidate
      - commits it
    but with WEALL_TEST_SLEEP_AFTER_BLOCK_INSERT_MS set so the child sleeps
    *after* inserting the block row and *before* writing ledger_state.

    The parent SIGKILLs the child during that window.

    Expected: on restart, there are no blocks and height==0, and mempool still
    contains the tx.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    child_code = r'''
import os
from weall.runtime.executor import WeAllExecutor

ex = WeAllExecutor(
    db_path=os.environ["DB_PATH"],
    node_id="alice",
    chain_id="sigkill",
    tx_index_path=os.environ["TX_INDEX"],
)
sub = ex.submit_tx({"tx_type":"ACCOUNT_REGISTER","signer":"user0","nonce":1,"payload":{"pubkey":"k:0"}})
assert sub.get("ok") is True

blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
assert err == ""

meta = ex.commit_block_candidate(block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)
# If we didn't get killed, we should have succeeded.
assert meta.ok is True
'''

    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["DB_PATH"] = db_path
    env["TX_INDEX"] = tx_index_path
    env["WEALL_TEST_SLEEP_AFTER_BLOCK_INSERT_MS"] = "5000"
    marker = str(tmp_path / "child_ready.marker")
    env["WEALL_TEST_MARKER_PATH"] = marker

    p = subprocess.Popen([sys.executable, "-c", child_code], env=env)

    # Wait until the child signals it has inserted the block row and entered the sleep window.
    deadline = time.time() + 8.0
    while time.time() < deadline and not Path(marker).exists():
        time.sleep(0.02)
    assert Path(marker).exists(), "child did not reach post-insert window"

    # SIGKILL hard stop.
    os.kill(p.pid, signal.SIGKILL)
    p.wait(timeout=10)

    # Restart executor; DB must be consistent and rolled back.
    ex2 = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="sigkill", tx_index_path=tx_index_path)
    assert int(ex2.read_state().get("height", 0)) == 0
    assert ex2.get_latest_block() is None

    pending = ex2.mempool.peek(limit=10)
    assert isinstance(pending, list)
    assert len(pending) >= 1
