from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_state(ex: WeAllExecutor, state: dict) -> None:
    ex._store.write_state_snapshot(state)  # type: ignore[attr-defined]
    ex.state = ex.read_state()


def _bootstrap_content_account(ex: WeAllExecutor, account_id: str = "@alice") -> None:
    state = ex.read_state()
    accounts = dict(state.get("accounts") or {})
    accounts[account_id] = {
        "banned": False,
        "devices": {"by_id": {}},
        "keys": {
            "by_id": {
                f"k:{account_id}": {
                    "key_type": "main",
                    "pubkey": f"k:{account_id}",
                    "revoked": False,
                    "revoked_at": None,
                }
            }
        },
        "locked": False,
        "nonce": 1,
        "poh_tier": 3,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 0,
        "session_keys": {},
    }
    state["accounts"] = accounts
    _write_state(ex, state)


def _seed_protocol_treasury_open_spend(ex: WeAllExecutor) -> None:
    state = ex.read_state()
    state["height"] = 10
    accounts = dict(state.get("accounts") or {})
    accounts["alice"] = {"nonce": 1, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1.0}
    accounts["bob"] = {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1.0}
    accounts["SYSTEM"] = {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1.0}
    state["accounts"] = accounts
    roles = dict(state.get("roles") or {})
    roles["emissaries"] = {"seated": ["alice", "bob"]}
    roles["treasuries_by_id"] = {
        "t1": {
            "signers": ["alice", "bob"],
            "threshold": 2,
            "created_by": "SYSTEM",
            "require_emissary_signers": True,
        }
    }
    state["roles"] = roles
    params = dict(state.get("params") or {})
    params.update({"economic_unlock_time": 0, "economics_enabled": True, "system_signer": "SYSTEM"})
    state["params"] = params
    state["treasury"] = {
        "spends": {
            "sp1": {
                "spend_id": "sp1",
                "treasury_id": "t1",
                "status": "proposed",
                "threshold": 2,
                "allowed_signers": ["alice", "bob"],
                "signatures": {"alice": {"at_nonce": 1}},
                "earliest_execute_height": 1,
                "payload": {"amount": 5},
            }
        }
    }
    _write_state(ex, state)


def test_transition_guardrail_diagnostics_persist_across_restart_batch112(tmp_path: Path) -> None:
    repo_root = _repo_root()
    db_path = str(tmp_path / "guardrails.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@leader",
        chain_id="guardrails-b112",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    _seed_protocol_treasury_open_spend(ex)

    sub = ex.submit_tx(
        {
            "tx_type": "TREASURY_SIGNERS_SET",
            "signer": "alice",
            "nonce": 2,
            "payload": {"treasury_id": "t1", "signers": ["alice", "bob"], "threshold": 2},
        }
    )
    assert sub["ok"] is True

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True

    diag = ex.transition_guardrail_diagnostics()
    assert diag["height"] == 11
    assert diag["rejection_count"] == 1
    assert diag["reason_counts"]["treasury_spend_open"] == 1
    assert diag["tx_type_counts"]["TREASURY_SIGNERS_SET"]["treasury_spend_open"] == 1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@leader",
        chain_id="guardrails-b112",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    diag2 = ex2.transition_guardrail_diagnostics()
    assert diag2["reason_counts"]["treasury_spend_open"] == 1
    assert diag2["recent_events"][0]["tx_type"] == "TREASURY_SIGNERS_SET"


def test_helper_execution_replay_marker_and_summary_survive_follower_restart_batch112(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    repo_root = _repo_root()
    leader_db = str(tmp_path / "leader.db")
    follower_db = str(tmp_path / "follower.db")

    leader = WeAllExecutor(
        db_path=leader_db,
        node_id="@leader",
        chain_id="helper-replay-b112",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    follower = WeAllExecutor(
        db_path=follower_db,
        node_id="@follower",
        chain_id="helper-replay-b112",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    _bootstrap_content_account(leader, "@alice")
    _bootstrap_content_account(follower, "@alice")

    sub = leader.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "body": "hello helper replay",
                "visibility": "public",
                "tags": ["batch112"],
                "media": [],
            },
        }
    )
    assert sub["ok"] is True

    block, new_state, applied_ids, invalid_ids, err = leader.build_block_candidate(max_txs=1)
    assert err == ""
    leader_meta = leader.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert leader_meta.ok is True

    follower_meta = follower.apply_block(block)
    assert follower_meta.ok is True

    diag = follower.helper_execution_diagnostics()
    assert diag["height"] == 1
    assert diag["summary"]["lane_count"] == 1
    assert diag["summary"]["helper_lane_count"] == 0
    assert diag["summary"]["fallback_lane_count"] == 1
    assert diag["summary"]["fallback_reason_counts"]["capability_miss"] == 1

    follower2 = WeAllExecutor(
        db_path=follower_db,
        node_id="@follower",
        chain_id="helper-replay-b112",
        tx_index_path=str(repo_root / "generated" / "tx_index.json"),
    )
    diag2 = follower2.helper_execution_diagnostics()
    assert diag2["summary"]["lane_count"] == 1
    assert diag2["summary"]["fallback_reason_counts"]["capability_miss"] == 1
