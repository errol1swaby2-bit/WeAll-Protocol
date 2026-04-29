from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
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
    accounts = dict(state.get("accounts") or {})
    accounts["alice"] = {
        "nonce": 1,
        "poh_tier": 3,
        "banned": False,
        "locked": False,
        "reputation": 1.0,
    }
    accounts["bob"] = {
        "nonce": 0,
        "poh_tier": 3,
        "banned": False,
        "locked": False,
        "reputation": 1.0,
    }
    accounts["SYSTEM"] = {
        "nonce": 0,
        "poh_tier": 3,
        "banned": False,
        "locked": False,
        "reputation": 1.0,
    }
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
    params.update({"economic_unlock_time": 0, "economics_enabled": False, "system_signer": "SYSTEM"})
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


def _mk_executor(tmp_path: Path, name: str, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _status_client(ex: WeAllExecutor) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = ex
    return TestClient(app)


def _commit_next_block(ex: WeAllExecutor, *, max_txs: int = 10):
    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=max_txs)
    assert err == ""
    meta = ex.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is True
    return block


def test_cross_node_forensics_converge_after_remote_apply_and_restart_batch114(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    chain_id = "batch114-forensics"
    leader = _mk_executor(tmp_path, "leader", chain_id)
    follower = _mk_executor(tmp_path, "follower", chain_id)

    _bootstrap_content_account(leader, "@alice")
    _bootstrap_content_account(follower, "@alice")

    ok1 = leader.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "body": "cross-node helper batch114",
                "visibility": "public",
                "tags": ["batch114"],
                "media": [],
            },
        }
    )
    assert ok1["ok"] is True
    helper_block = _commit_next_block(leader, max_txs=1)
    helper_replay = follower.apply_block(helper_block)
    assert helper_replay.ok is True

    _seed_protocol_treasury_open_spend(leader)
    _seed_protocol_treasury_open_spend(follower)

    ok2 = leader.submit_tx(
        {
            "tx_type": "TREASURY_SIGNERS_SET",
            "signer": "alice",
            "nonce": 2,
            "payload": {"treasury_id": "t1", "signers": ["alice", "bob"], "threshold": 2},
        }
    )
    assert ok2["ok"] is True
    guardrail_block = _commit_next_block(leader, max_txs=1)
    guardrail_replay = follower.apply_block(guardrail_block)
    assert guardrail_replay.ok is True

    leader_client = _status_client(leader)
    follower_client = _status_client(follower)

    leader_consensus = leader_client.get("/v1/status/consensus").json()
    follower_consensus = follower_client.get("/v1/status/consensus").json()
    assert leader_consensus["helper_execution"]["summary"] == follower_consensus["helper_execution"]["summary"]
    assert leader_consensus["transition_guardrails"]["reason_counts"] == follower_consensus["transition_guardrails"]["reason_counts"]
    assert leader_consensus["helper_reputation"] == follower_consensus["helper_reputation"]

    leader_forensics = leader_client.get("/v1/status/consensus/forensics").json()
    follower_forensics = follower_client.get("/v1/status/consensus/forensics").json()
    assert leader_forensics["helper_execution"]["summary"] == follower_forensics["helper_execution"]["summary"]
    assert leader_forensics["transition_guardrails"]["tx_type_counts"] == follower_forensics["transition_guardrails"]["tx_type_counts"]
    assert leader_forensics["helper_reputation"] == follower_forensics["helper_reputation"]

    follower_restarted = _mk_executor(tmp_path, "follower", chain_id)
    restarted_client = _status_client(follower_restarted)
    restarted_consensus = restarted_client.get("/v1/status/consensus").json()
    restarted_operator = restarted_client.get("/v1/status/operator").json()

    assert restarted_consensus["helper_execution"]["summary"] == leader_consensus["helper_execution"]["summary"]
    assert restarted_consensus["transition_guardrails"]["reason_counts"] == leader_consensus["transition_guardrails"]["reason_counts"]
    assert restarted_consensus["helper_reputation"] == leader_consensus["helper_reputation"]
    assert restarted_operator["operator"]["helper_execution"]["summary"] == leader_consensus["helper_execution"]["summary"]
    assert restarted_operator["operator"]["transition_guardrails"]["reason_counts"] == leader_consensus["transition_guardrails"]["reason_counts"]
    assert restarted_operator["operator"]["helper_reputation"] == leader_consensus["helper_reputation"]
