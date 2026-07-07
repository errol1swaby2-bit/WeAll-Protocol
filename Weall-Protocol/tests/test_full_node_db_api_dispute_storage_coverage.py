from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))


def _run_json(script: str) -> dict[str, Any]:
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--json"], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(proc.stdout)


def _proof() -> dict[str, Any]:
    return json.loads((ROOT / "generated" / "b534_b538_completion_proof_v1_5.json").read_text(encoding="utf-8"))


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any] | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="sig", system=system, parent=parent)


def test_full_node_process_validator_rehearsal_uses_fastapi_processes() -> None:
    out = _proof()["validator_rehearsal"]
    assert out["ok"] is True
    assert out["process_model"] == "actual_fastapi_uvicorn_processes"
    assert out["network_transport"] == "127.0.0.1_http_json"
    assert out["readyz_route_checked"] is True
    assert out["ports_bound"] == 4
    assert out["minority_partition_result"] == "finality_threshold_not_met"
    assert out["restart_root_preserved"] is True
    assert out["lagging_rejoin_root_matches_reference"] is True
    assert out["observer_vote_rejected"] is True
    assert out["public_validator_enabled"] is False


def test_real_db_block_replay_sync_uses_commit_tables_and_rejects_corrupt_blocks() -> None:
    out = _proof()["replay_sync"]
    assert out["ok"] is True
    assert out["source_db_backed"] is True
    assert out["fresh_db_backed"] is True
    assert out["block_commit_tables_used"] == ["blocks", "block_hash_index", "ledger_state"]
    assert out["receipt_roots_verified"] is True
    assert out["block_hashes_verified"] is True
    assert out["interrupted_resume_verified"] is True
    assert out["corrupt_block_rejected"] is True
    assert out["source_state_root"] == out["fresh_state_root"]


def test_fully_api_driven_lifecycle_exercises_core_api_surfaces_and_boundaries() -> None:
    out = _proof()["api_lifecycle"]
    assert out["ok"] is True
    assert out["api_route_count"] >= 6
    assert "GET /v1/session/me" in out["api_routes_exercised"]
    assert "GET /v1/feed?rank=production" in out["api_routes_exercised"]
    assert "GET /v1/groups/{group_id}" in out["api_routes_exercised"]
    assert "GET /v1/activity/notices" in out["api_routes_exercised"]
    assert out["public_activity_checked"] is True
    assert out["feed_ranking"]["mode"] == "production"
    assert out["poh_reverification_status"] == "completed"
    assert out["dispute_remedy_applied"] is True
    assert out["storage_retrieval_confirmed"] is True
    assert out["economics_locked_rejection"] is True
    assert out["protocol_upgrade_record_only"] is True


def test_dispute_appeal_remedy_can_reinstate_account_and_role_eligibility() -> None:
    state: dict[str, Any] = {
        "height": 5,
        "accounts": {
            "@target": {"poh_tier": 2, "restricted": True, "locked": True, "latest_restriction": "review"},
            "@juror": {"poh_tier": 2, "dispute_juror_eligible": False, "dispute_juror_suspended_reason": "assigned_dispute_vote_missed"},
            "SYSTEM": {"poh_tier": 0},
        },
        "disputes_by_id": {
            "d-remedy": {
                "dispute_id": "d-remedy",
                "target_type": "account",
                "target_id": "@target",
                "stage": "appealed",
                "appeals": [{"by": "@target"}],
                "assigned_jurors": ["@juror"],
                "votes": {"@juror": {"vote": "yes"}},
                "resolution": {"summary": "restrict", "actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "@target", "restriction": "review"}}]},
            }
        },
    }
    out = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 1, {"dispute_id": "d-remedy", "appeal_resolution": {"decision": "modify", "actions": [{"tx_type": "ACCOUNT_REINSTATE", "payload": {"account_id": "@target"}}, {"tx_type": "ROLE_ELIGIBILITY_SET", "payload": {"account_id": "@juror", "role": "dispute_juror", "eligible": True}}]}}, system=True, parent="d"))
    assert out["applied"] == "DISPUTE_FINAL_RECEIPT"
    assert state["accounts"]["@target"]["restricted"] is False
    assert state["accounts"]["@target"]["locked"] is False
    assert state["accounts"]["@target"]["remedies"][-1]["remedy"] == "account_reinstated"
    assert state["accounts"]["@juror"]["dispute_juror_eligible"] is True
    assert state["accounts"]["@juror"]["role_eligibility"]["dispute_juror"]["eligible"] is True


def test_storage_operator_durability_rehearses_failure_reassignment_and_retrieval() -> None:
    out = _proof()["storage_durability"]
    assert out["ok"] is True
    assert out["reassignment_recorded"] is True
    assert out["replacement_operator"] != out["failed_operator"]
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["retrieval_proof_count"] >= 1


def test_generated_proof_artifact_preserves_locks() -> None:
    proof = _proof()
    assert proof["ok"] is True
    assert proof["validator_rehearsal"]["process_model"] == "actual_fastapi_uvicorn_processes"
    assert proof["replay_sync"]["source_db_backed"] is True
    assert proof["api_lifecycle"]["ok"] is True
    assert proof["storage_durability"]["retrieval_confirmed"] is True
    assert proof["locked_boundaries"] == {
        "automatic_upgrades": False,
        "live_economics": False,
        "production_helpers": False,
        "public_validators": False,
    }
