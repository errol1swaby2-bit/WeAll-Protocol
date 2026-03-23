from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.runtime.execution_lanes import canonical_scope_prefixes


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
    consensus["validator_set"] = {
        "epoch": 7,
        "active_set": ["@leader", "@helper-a", "@helper-b"],
    }
    st["consensus"] = consensus
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]
    ex.state = ex._store.read()  # type: ignore[attr-defined]



def test_scope_prefixes_infer_from_tx_type() -> None:
    tx = {
        "tx_type": "CONTENT_POST_CREATE",
        "signer": "@alice",
        "nonce": 2,
        "payload": {"body": "hello", "visibility": "public", "tags": [], "media": []},
    }
    assert canonical_scope_prefixes(tx) == ("content:",)



def test_build_block_candidate_emits_helper_execution_metadata(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    repo_root = _repo_root()
    ex = WeAllExecutor(
        db_path=str(tmp_path / "helper_exec.db"),
        node_id="@leader",
        chain_id="helper-executor-int",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    _bootstrap_account(ex, account_id="@alice")

    ok = ex.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "body": "first helper-routed post",
                "visibility": "public",
                "tags": ["alpha"],
                "media": [],
            },
        }
    )
    assert ok["ok"] is True

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1)
    assert err == ""
    assert block is not None
    assert new_state is not None
    assert len(applied_ids) == 1
    assert invalid_ids == []

    helper_execution = block.get("helper_execution")
    assert isinstance(helper_execution, dict)
    assert helper_execution.get("enabled") is True
    lanes = helper_execution.get("lanes")
    assert isinstance(lanes, list)
    assert len(lanes) >= 1
    content_lane = [lane for lane in lanes if lane.get("lane_id") == "PARALLEL_CONTENT"]
    assert len(content_lane) == 1
    assert content_lane[0].get("helper_id") in {"@helper-a", "@helper-b"}

    marker = new_state.get("meta", {}).get("helper_execution_last")
    assert isinstance(marker, dict)
    assert marker.get("height") == block.get("height")
    assert marker.get("validator_epoch") == 7



def test_commit_persists_helper_execution_replay_marker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    repo_root = _repo_root()
    ex = WeAllExecutor(
        db_path=str(tmp_path / "helper_commit.db"),
        node_id="@leader",
        chain_id="helper-executor-commit",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    _bootstrap_account(ex, account_id="@alice")

    assert (
        ex.submit_tx(
            {
                "tx_type": "CONTENT_POST_CREATE",
                "signer": "@alice",
                "nonce": 2,
                "payload": {
                    "body": "persist me",
                    "visibility": "public",
                    "tags": ["beta"],
                    "media": [],
                },
            }
        )["ok"]
        is True
    )

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1)
    assert err == ""
    meta = ex.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is True

    ex2 = WeAllExecutor(
        db_path=str(tmp_path / "helper_commit.db"),
        node_id="@leader",
        chain_id="helper-executor-commit",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    marker = ex2.state.get("meta", {}).get("helper_execution_last")
    assert isinstance(marker, dict)
    assert marker.get("height") == 1
    lane_ids = {lane.get("lane_id") for lane in marker.get("lanes", []) if isinstance(lane, dict)}
    assert "PARALLEL_CONTENT" in lane_ids
