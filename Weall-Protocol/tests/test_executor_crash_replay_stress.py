# tests/test_executor_crash_replay_stress.py
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _wait_for_marker(marker: Path, timeout_s: float = 8.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline and not marker.exists():
        time.sleep(0.02)
    assert marker.exists(), "child did not reach post-insert window"


def test_repeated_sigkill_does_not_corrupt_db_and_replay_is_deterministic(tmp_path: Path) -> None:
    """Stress-ish crash test:

    Repeat a SIGKILL in the atomic-commit danger window several times, each time
    ensuring:
      - DB rolls back to a consistent height (no partial block persisted)
      - mempool retains the submitted txs

    Then finalize by producing blocks normally and verifying a clean restart
    yields the same tip and roots.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    child_code = r'''
import os
from weall.runtime.executor import WeAllExecutor

ex = WeAllExecutor(
    db_path=os.environ["DB_PATH"],
    node_id="@alice",
    chain_id="crashstress",
    tx_index_path=os.environ["TX_INDEX"],
)

signer = os.environ["SIGNER"]
sub = ex.submit_tx({"tx_type":"ACCOUNT_REGISTER","signer":signer,"nonce":1,"payload":{"pubkey":f"k:{signer}"}})
assert sub.get("ok") is True

blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
assert err == ""

meta = ex.commit_block_candidate(block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)
assert meta.ok is True
'''

    # Repeatedly crash in the commit window.
    for i in range(3):
        marker = Path(tmp_path / f"child_ready_{i}.marker")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["DB_PATH"] = db_path
        env["TX_INDEX"] = tx_index_path
        env["SIGNER"] = f"@user{i}"
        env["WEALL_TEST_SLEEP_AFTER_BLOCK_INSERT_MS"] = "5000"
        env["WEALL_TEST_MARKER_PATH"] = str(marker)

        p = subprocess.Popen([sys.executable, "-c", child_code], env=env)
        _wait_for_marker(marker)

        p.kill()
        p.wait(timeout=5)

        # Restart and verify atomic rollback.
        ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="crashstress", tx_index_path=tx_index_path)
        st = ex.read_state()
        assert int(st.get("height", 0)) == 0

        mp = ex.read_mempool()
        # Each crashed attempt must leave its tx still pending.
        assert len(mp) == i + 1

    # Now produce blocks normally to clear the accumulated mempool.
    ex2 = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="crashstress", tx_index_path=tx_index_path)

    # Commit until mempool empty.
    for _ in range(10):
        mp = ex2.read_mempool()
        if not mp:
            break
        meta = ex2.produce_block(max_txs=1)
        assert meta.ok is True

    assert len(ex2.read_mempool()) == 0

    tip1 = ex2.get_latest_block()
    assert isinstance(tip1, dict)
    h1 = int(tip1.get("header", {}).get("height") or 0)
    assert h1 >= 1

    # Hard restart: must converge to identical tip + roots.
    ex3 = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="crashstress", tx_index_path=tx_index_path)
    tip2 = ex3.get_latest_block()
    assert isinstance(tip2, dict)

    assert str(tip1.get("block_id") or "") == str(tip2.get("block_id") or "")

    hdr1 = tip1.get("header") or {}
    hdr2 = tip2.get("header") or {}

    for k in ("state_root", "receipts_root"):
        v1 = str(hdr1.get(k) or "")
        v2 = str(hdr2.get(k) or "")
        if v1 or v2:
            assert v1 == v2
