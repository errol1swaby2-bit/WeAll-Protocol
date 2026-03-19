from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.runtime.fault_injection import _build_committed_block, _make_qc, _mk_keypair_hex, _seed_validator_set


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _seed_bft_executor(db_path: str, chain_id: str, validators: list[str], vpub: dict[str, str]) -> WeAllExecutor:
    ex = WeAllExecutor(db_path=db_path, node_id=validators[0], chain_id=chain_id, tx_index_path=str(_repo_root() / "generated" / "tx_index.json"))
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)
    ex._bft_enabled = True
    return ex


def test_block_commit_failpoint_before_ledger_state_preserves_atomicity(tmp_path: Path, monkeypatch) -> None:
    db_path = str(tmp_path / "atomic.db")
    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="priority3-atomic", tx_index_path=str(_repo_root() / "generated" / "tx_index.json"))
    sub = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "@user0", "nonce": 1, "payload": {"pubkey": "k:0"}})
    assert sub["ok"] is True

    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
    assert err == ""

    monkeypatch.setenv("WEALL_TEST_FAILPOINTS", "block_commit_before_ledger_state")
    meta = ex.commit_block_candidate(block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)
    assert meta.ok is False
    assert "commit_failed" in meta.error

    ex2 = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="priority3-atomic", tx_index_path=str(_repo_root() / "generated" / "tx_index.json"))
    st = ex2.read_state()
    assert int(st.get("height", 0)) == 0
    assert len(ex2.read_mempool()) == 1
    with ex2._db._connect() as con:
        rows = list(con.execute("SELECT tx_id FROM tx_index;"))
    assert rows == []


def test_bft_finalized_frontier_failpoint_does_not_partially_persist(tmp_path: Path, monkeypatch) -> None:
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    db_path = str(tmp_path / "bft.db")
    ex = _seed_bft_executor(db_path, "priority3-bft", validators, vpub)

    _b1 = _build_committed_block(ex, force_ts_ms=1_000)
    _b2 = _build_committed_block(ex, force_ts_ms=2_000)
    b3 = _build_committed_block(ex, force_ts_ms=3_000)
    assert str(ex._bft.finalized_block_id or "") == ""

    monkeypatch.setenv("WEALL_TEST_FAILPOINTS", "bft_finalized_frontier_advanced")
    qc = _make_qc(
        chain_id="priority3-bft",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id=str(b3.get("block_id") or ""),
        block_hash=str(b3.get("block_hash") or ""),
        parent_id=str(b3.get("prev_block_id") or ""),
        view=7,
        validator_epoch=3,
        validator_set_hash=str(ex._current_validator_set_hash() or ""),
    )
    try:
        ex.bft_handle_qc(qc)
        assert False, "expected failpoint-triggered exception"
    except RuntimeError as exc:
        assert "failpoint:bft_finalized_frontier_advanced" in str(exc)

    ex2 = _seed_bft_executor(db_path, "priority3-bft", validators, vpub)
    assert str(ex2._bft.finalized_block_id or "") == ""
    assert int(ex2.read_state().get("height", 0)) == 3


def test_bft_state_persist_exit_drill_recovers_cleanly(tmp_path: Path) -> None:
    root = _repo_root()
    db_path = str(tmp_path / "exit.db")
    marker_dir = str(tmp_path / "markers")
    child_code = """
import os
from weall.runtime.executor import WeAllExecutor

ex = WeAllExecutor(
    db_path=os.environ['DB_PATH'],
    node_id='@alice',
    chain_id='priority3-exit',
    tx_index_path=os.environ['TX_INDEX'],
)
ex.bft_set_view(9)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["DB_PATH"] = db_path
    env["TX_INDEX"] = str(root / "generated" / "tx_index.json")
    env["WEALL_TEST_FAILPOINTS"] = "bft_state_before_persist"
    env["WEALL_TEST_FAILPOINT_ACTION"] = "exit"
    env["WEALL_TEST_FAILPOINT_MARKER_DIR"] = marker_dir
    proc = subprocess.run([sys.executable, "-c", child_code], env=env)
    assert proc.returncode == 91
    assert (Path(marker_dir) / "bft_state_before_persist.marker").exists()

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="priority3-exit", tx_index_path=str(root / "generated" / "tx_index.json"))
    assert ex.bft_current_view() == 0
    assert int(ex.read_state().get("height", 0)) == 0
