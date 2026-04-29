from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_executor(tmp_path: Path, name: str, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


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


def test_cross_node_mempool_selection_marker_converges_after_remote_apply_and_restart_batch115(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")

    chain_id = "batch115-mempool-selection"
    leader = _mk_executor(tmp_path, "leader", chain_id)
    follower = _mk_executor(tmp_path, "follower", chain_id)

    _bootstrap_content_account(leader, "@alice")
    _bootstrap_content_account(follower, "@alice")
    _bootstrap_content_account(leader, "@bob")
    _bootstrap_content_account(follower, "@bob")

    ok1 = leader.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "body": "cross-node mempool selection batch115",
                "visibility": "public",
                "tags": ["batch115"],
                "media": [],
            },
        }
    )
    assert ok1["ok"] is True

    ok2 = leader.submit_tx(
        {
            "tx_type": "PROFILE_UPDATE",
            "signer": "@bob",
            "nonce": 2,
            "payload": {"display_name": "Bob Batch115"},
        }
    )
    assert ok2["ok"] is True

    block = _commit_next_block(leader, max_txs=10)
    replay = follower.apply_block(block)
    assert replay.ok is True

    leader_client = _status_client(leader)
    follower_client = _status_client(follower)

    leader_consensus = leader_client.get("/v1/status/consensus").json()
    follower_consensus = follower_client.get("/v1/status/consensus").json()
    assert leader_consensus["mempool_selection_last"] == follower_consensus["mempool_selection_last"]
    assert leader_consensus["mempool_selection_last"]["policy"] == "canonical"
    assert leader_consensus["mempool_selection_last"]["selected_count"] == 2

    leader_forensics = leader_client.get("/v1/status/consensus/forensics").json()
    follower_forensics = follower_client.get("/v1/status/consensus/forensics").json()
    assert leader_forensics["mempool_selection_last"] == follower_forensics["mempool_selection_last"]

    leader_operator = leader_client.get("/v1/status/operator").json()
    follower_operator = follower_client.get("/v1/status/operator").json()
    assert leader_operator["operator"]["mempool_selection_last"] == follower_operator["operator"]["mempool_selection_last"]

    follower_restarted = _mk_executor(tmp_path, "follower", chain_id)
    restarted_client = _status_client(follower_restarted)
    restarted_consensus = restarted_client.get("/v1/status/consensus").json()
    restarted_forensics = restarted_client.get("/v1/status/consensus/forensics").json()
    restarted_operator = restarted_client.get("/v1/status/operator").json()

    assert restarted_consensus["mempool_selection_last"] == leader_consensus["mempool_selection_last"]
    assert restarted_forensics["mempool_selection_last"] == leader_forensics["mempool_selection_last"]
    assert restarted_operator["operator"]["mempool_selection_last"] == leader_operator["operator"]["mempool_selection_last"]
