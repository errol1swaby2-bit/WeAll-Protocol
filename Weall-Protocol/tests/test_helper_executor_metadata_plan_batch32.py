from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.runtime.parallel_execution import canonical_helper_execution_plan_fingerprint


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _bootstrap_account(ex: WeAllExecutor, *, account_id: str) -> None:
    st = dict(ex.state)
    accounts = st.get("accounts") if isinstance(st.get("accounts"), dict) else {}
    accounts[account_id] = {
        "pubkeys": [f"k:{account_id}"],
        "nonce": 1,
        "poh_tier": 3,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 0,
        "session_keys": {},
    }
    st["accounts"] = accounts
    consensus = st.get("consensus") if isinstance(st.get("consensus"), dict) else {}
    consensus["validator_set"] = {"epoch": 7, "active_set": ["@leader", "@helper-a", "@helper-b"]}
    st["consensus"] = consensus
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]
    ex.state = ex._store.read()  # type: ignore[attr-defined]


def test_build_block_candidate_emits_recomputable_helper_plan_id_batch32(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")
    ex = WeAllExecutor(
        db_path=str(tmp_path / "helper_exec.db"),
        node_id="@leader",
        chain_id="helper-executor-int",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    _bootstrap_account(ex, account_id="@alice")
    assert ex.submit_tx({"tx_type": "CONTENT_POST_CREATE", "signer": "@alice", "nonce": 2, "payload": {"body": "hello", "visibility": "public", "tags": [], "media": []}})["ok"] is True
    block, _new_state, _applied_ids, _invalid_ids, err = ex.build_block_candidate(max_txs=1)
    assert err == ""
    helper_execution = block.get("helper_execution")
    assert isinstance(helper_execution, dict)
    lanes = helper_execution.get("lanes")
    assert isinstance(lanes, list)
    assert helper_execution.get("plan_id") == canonical_helper_execution_plan_fingerprint(lanes)
    assert all(isinstance(l, dict) and "descriptor_hash" in l for l in lanes)
