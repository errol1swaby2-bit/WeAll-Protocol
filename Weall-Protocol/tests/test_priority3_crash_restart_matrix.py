from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _build_one_tx_block(ex: WeAllExecutor) -> tuple[dict, dict, list[str], list[str]]:
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
    assert isinstance(blk, dict)
    assert isinstance(st2, dict)
    return blk, st2, applied_ids, invalid_ids


def test_sqlite_before_commit_failpoint_rolls_back_atomic_block_commit_batch104(
    tmp_path: Path, monkeypatch
) -> None:
    db_path = str(tmp_path / "before-commit.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="priority3-before-commit",
        tx_index_path=_tx_index_path(),
    )
    blk, st2, applied_ids, invalid_ids = _build_one_tx_block(ex)

    monkeypatch.setenv("WEALL_TEST_FAILPOINTS", "sqlite_write_tx_before_commit")
    meta = ex.commit_block_candidate(
        block=blk,
        new_state=st2,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is False
    assert "commit_failed" in meta.error
    monkeypatch.delenv("WEALL_TEST_FAILPOINTS", raising=False)

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="priority3-before-commit",
        tx_index_path=_tx_index_path(),
    )
    st = ex2.read_state()
    assert int(st.get("height", 0)) == 0
    assert len(ex2.read_mempool()) == 1
    with ex2._db._connect() as con:
        assert list(con.execute("SELECT block_id FROM blocks;")) == []
        assert list(con.execute("SELECT tx_id FROM tx_index;")) == []


def test_block_commit_after_ledger_state_failpoint_rolls_back_epoch_transition_batch104(
    tmp_path: Path, monkeypatch
) -> None:
    db_path = str(tmp_path / "epoch-rollback.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="priority3-epoch-rollback",
        tx_index_path=_tx_index_path(),
    )
    blk, st2, applied_ids, invalid_ids = _build_one_tx_block(ex)

    st2.setdefault("consensus", {})
    st2["consensus"].setdefault("epochs", {})
    st2["consensus"]["epochs"]["current"] = 2
    st2["consensus"].setdefault("validator_set", {})
    st2["consensus"]["validator_set"]["epoch"] = 2
    st2["consensus"]["validator_set"]["active_set"] = ["v1", "v2", "v3"]
    st2.setdefault("roles", {})
    st2["roles"].setdefault("validators", {})
    st2["roles"]["validators"]["active_set"] = ["v1", "v2", "v3"]

    monkeypatch.setenv("WEALL_TEST_FAILPOINTS", "block_commit_after_ledger_state")
    meta = ex.commit_block_candidate(
        block=blk,
        new_state=st2,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is False
    assert "commit_failed" in meta.error
    monkeypatch.delenv("WEALL_TEST_FAILPOINTS", raising=False)

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="priority3-epoch-rollback",
        tx_index_path=_tx_index_path(),
    )
    st = ex2.read_state()
    assert int(st.get("height", 0)) == 0
    assert int(st.get("consensus", {}).get("epochs", {}).get("current", 0)) == 0
    assert st.get("roles", {}).get("validators", {}).get("active_set", []) == []


def test_sqlite_after_commit_exit_preserves_committed_block_batch104(tmp_path: Path) -> None:
    root = _repo_root()
    db_path = str(tmp_path / "after-commit.db")
    marker_dir = str(tmp_path / "markers-block")
    child_code = """
import os
from weall.runtime.executor import WeAllExecutor

ex = WeAllExecutor(
    db_path=os.environ['DB_PATH'],
    node_id='@alice',
    chain_id='priority3-after-commit',
    tx_index_path=os.environ['TX_INDEX'],
)
sub = ex.submit_tx({
    'tx_type': 'ACCOUNT_REGISTER',
    'signer': '@user0',
    'nonce': 1,
    'payload': {'pubkey': 'k:0'},
})
assert sub['ok'] is True
blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
assert err == ''
os.environ['WEALL_TEST_FAILPOINTS'] = 'sqlite_write_tx_after_commit'
os.environ['WEALL_TEST_FAILPOINT_ACTION'] = 'exit'
os.environ['WEALL_TEST_FAILPOINT_MARKER_DIR'] = os.environ['MARKER_DIR']
meta = ex.commit_block_candidate(block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)
assert meta.ok is True
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["DB_PATH"] = db_path
    env["TX_INDEX"] = _tx_index_path()
    env["MARKER_DIR"] = marker_dir
    proc = subprocess.run([sys.executable, "-c", child_code], env=env)
    assert proc.returncode == 91
    assert (Path(marker_dir) / "sqlite_write_tx_after_commit.marker").exists()

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="priority3-after-commit",
        tx_index_path=_tx_index_path(),
    )
    st = ex.read_state()
    assert int(st.get("height", 0)) == 1
    assert len(ex.read_mempool()) == 0
    with ex._db._connect() as con:
        assert len(list(con.execute("SELECT block_id FROM blocks;"))) == 1
        assert len(list(con.execute("SELECT tx_id FROM tx_index;"))) == 1


def test_bft_state_after_persist_exit_keeps_view_and_epoch_batch104(tmp_path: Path) -> None:
    root = _repo_root()
    db_path = str(tmp_path / "bft-after-persist.db")
    marker_dir = str(tmp_path / "markers-bft")
    child_code = """
import os
from weall.runtime.executor import WeAllExecutor

ex = WeAllExecutor(
    db_path=os.environ['DB_PATH'],
    node_id='@alice',
    chain_id='priority3-bft-after-persist',
    tx_index_path=os.environ['TX_INDEX'],
)
st = ex.read_state()
st.setdefault('consensus', {})
st['consensus'].setdefault('epochs', {})
st['consensus']['epochs']['current'] = 4
st['consensus'].setdefault('validator_set', {})
st['consensus']['validator_set']['epoch'] = 4
st['consensus']['validator_set']['active_set'] = ['v1', 'v2', 'v3', 'v4']
st.setdefault('roles', {})
st['roles'].setdefault('validators', {})
st['roles']['validators']['active_set'] = ['v1', 'v2', 'v3', 'v4']
ex.state = st
ex._ledger_store.write(ex.state)
ex.bft_set_view(9)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["DB_PATH"] = db_path
    env["TX_INDEX"] = _tx_index_path()
    env["WEALL_TEST_FAILPOINTS"] = "bft_state_after_persist"
    env["WEALL_TEST_FAILPOINT_ACTION"] = "exit"
    env["WEALL_TEST_FAILPOINT_MARKER_DIR"] = marker_dir
    proc = subprocess.run([sys.executable, "-c", child_code], env=env)
    assert proc.returncode == 91
    assert (Path(marker_dir) / "bft_state_after_persist.marker").exists()

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="priority3-bft-after-persist",
        tx_index_path=_tx_index_path(),
    )
    st = ex.read_state()
    assert int(st.get("consensus", {}).get("epochs", {}).get("current", 0)) == 4
    assert ex.bft_current_view() == 9
