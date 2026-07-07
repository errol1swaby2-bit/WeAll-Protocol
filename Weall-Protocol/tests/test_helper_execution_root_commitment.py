from __future__ import annotations

import copy
from pathlib import Path

from weall.runtime.block_hash import compute_helper_execution_root
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _new_executor(tmp_path: Path) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@leader",
        chain_id="helper-root-test",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _bootstrap_account(ex: WeAllExecutor, *, account_id: str) -> None:
    st = dict(ex.state)
    accounts = st.get("accounts") if isinstance(st.get("accounts"), dict) else {}
    accounts[account_id] = {
        "pubkeys": [f"k:{account_id}"],
        "nonce": 1,
        "poh_tier": 2,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 0,
        "session_keys": {},
    }
    st["accounts"] = accounts
    consensus = st.get("consensus") if isinstance(st.get("consensus"), dict) else {}
    consensus["validator_set"] = {"epoch": 7, "active_set": ["@leader", "@helper-a", "@helper-b"]}
    st["consensus"] = consensus
    ex._ledger_store.write_state_snapshot(st)  # type: ignore[attr-defined]
    ex.state = ex._ledger_store.read()  # type: ignore[attr-defined]


def _helper_block(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")
    leader = _new_executor(tmp_path / "leader")
    follower = _new_executor(tmp_path / "follower")
    _bootstrap_account(leader, account_id="@alice")
    _bootstrap_account(follower, account_id="@alice")
    assert leader.submit_tx({
        "tx_type": "CONTENT_POST_CREATE",
        "signer": "@alice",
        "nonce": 2,
        "payload": {"body": "hello", "visibility": "public", "tags": [], "media": []},
    })["ok"] is True
    block, _new_state, _applied_ids, _invalid_ids, err = leader.build_block_candidate(max_txs=1)
    assert err == ""
    assert isinstance(block.get("helper_execution"), dict)
    return follower, block


def test_helper_execution_root_is_in_header_when_helper_metadata_exists(tmp_path: Path, monkeypatch) -> None:
    _follower, block = _helper_block(tmp_path, monkeypatch)
    helper_execution = block.get("helper_execution")
    assert isinstance(helper_execution, dict)
    header = block.get("header")
    assert isinstance(header, dict)
    assert header.get("helper_execution_root") == compute_helper_execution_root(helper_execution=helper_execution)


def test_apply_block_rejects_tampered_helper_execution_metadata(tmp_path: Path, monkeypatch) -> None:
    follower, block = _helper_block(tmp_path, monkeypatch)
    tampered = copy.deepcopy(block)
    helper_execution = tampered.get("helper_execution")
    assert isinstance(helper_execution, dict)
    helper_execution["fraud_suspected"] = not bool(helper_execution.get("fraud_suspected"))

    res = follower.apply_block(tampered)

    assert res.ok is False
    assert res.error == "bad_block:helper_execution_root_mismatch"


def test_apply_block_rejects_helper_execution_without_header_root(tmp_path: Path, monkeypatch) -> None:
    follower, block = _helper_block(tmp_path, monkeypatch)
    missing = copy.deepcopy(block)
    header = missing.get("header")
    assert isinstance(header, dict)
    header.pop("helper_execution_root", None)
    missing.pop("block_hash", None)

    res = follower.apply_block(missing)

    assert res.ok is False
    assert res.error == "bad_block:missing_helper_execution_root"
