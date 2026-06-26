from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.poh import apply_poh
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))


class _FakeExecutor:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def _run_json(script: str) -> dict[str, Any]:
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--json"], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(proc.stdout)


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any] | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="sig", system=system, parent=parent)


def test_validator_rehearsal_uses_tcp_subprocesses_and_preserves_boundaries() -> None:
    out = json.loads((ROOT / "generated" / "b528_b532_completion_proof_v1_5.json").read_text())["validator_rehearsal"]
    assert out["ok"] is True
    assert out["process_model"] == "subprocess_tcp_json_rpc"
    assert out["network_transport"] == "127.0.0.1_tcp_json_lines"
    assert out["ports_bound"] == 4
    assert out["public_validator_enabled"] is False
    assert out["minority_partition_result"] == "finality_threshold_not_met"
    assert out["restart_root_preserved"] is True
    assert out["lagging_rejoin_root_matches_reference"] is True
    assert out["observer_vote_rejected"] is True


def test_db_backed_replay_sync_verifies_receipts_and_rejects_corrupt_blocks() -> None:
    out = _run_json("rehearse_db_backed_fresh_node_replay_sync_v1_5.py")
    assert out["ok"] is True
    assert out["durable_db_used"] is True
    assert out["receipt_roots_verified"] is True
    assert out["interrupted_resume_verified"] is True
    assert out["corrupt_block_rejected"] is True
    assert out["source_state_root"] == out["fresh_state_root"]


def test_api_driven_lifecycle_exercises_real_routes_and_locked_boundaries() -> None:
    from rehearse_api_driven_full_lifecycle_v1_5 import run_harness
    out = run_harness()
    assert out["ok"] is True
    assert "GET /v1/feed" in out["api_routes_exercised"]
    assert out["feed_ranking"]["mode"] == "production"
    assert out["public_activity_checked"] is True
    assert "GET /v1/activity/notices" in out["api_routes_exercised"]
    assert out["storage_retrieval_confirmed"] is True
    assert out["economics_locked_rejection"] is True
    assert out["protocol_upgrade_record_only"] is True


def test_poh_reviewer_accountability_updates_reviewer_eligibility() -> None:
    state: dict[str, Any] = {
        "height": 7,
        "accounts": {
            "@subject": {"poh_tier": 2, "nonce": 0},
            "@reviewer": {"poh_tier": 2, "nonce": 0},
            "@r2": {"poh_tier": 2, "nonce": 0},
            "@r3": {"poh_tier": 2, "nonce": 0},
            "SYSTEM": {"poh_tier": 0},
        },
        "roles": {"validators": {"active_set": ["@reviewer", "@r2", "@r3"]}, "poh_reviewers": {"active": {"@reviewer": True}}},
        "poh": {"async_cases": {}, "challenges": {}},
    }
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", "@subject", 1, {"case_id": "case-a", "account_id": "@subject", "evidence_commitment": "sha256:" + "c" * 64}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", "@subject", 2, {"case_id": "case-a", "evidence_id": "ev", "evidence_commitment": "sha256:" + "c" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 1, {"case_id": "case-a", "jurors": ["@reviewer", "@r2", "@r3"]}, system=True, parent="poh:case"))
    for i, reviewer in enumerate(["@reviewer", "@r2", "@r3"], start=1):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", reviewer, i, {"case_id": "case-a"}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", reviewer, i + 10, {"case_id": "case-a", "verdict": "approve"}))
    opened = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@r2", 30, {"account_id": "@subject", "case_id": "case-a"}))
    apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 31, {"challenge_id": opened["challenge_id"], "resolution": "upheld", "case_id": "case-a"}, system=True, parent="poh:challenge"))
    assert state["accounts"]["@reviewer"]["poh_reviewer_eligible"] is False
    assert state["poh"]["reviewer_accountability"]["by_reviewer"]["@reviewer"]["eligible_for_poh_review"] is False


def test_dispute_juror_inactivity_updates_juror_eligibility() -> None:
    state: dict[str, Any] = {
        "height": 11,
        "accounts": {"@open": {"poh_tier": 2}, "@j1": {"poh_tier": 2}, "@j2": {"poh_tier": 2}, "SYSTEM": {"poh_tier": 0}},
        "roles": {"validators": {"active_set": ["@j1", "@j2"]}},
        "system_queue": [],
    }
    apply_dispute(state, _env("DISPUTE_OPEN", "@open", 1, {"dispute_id": "d-inactive", "target_type": "account", "target_id": "@open", "reason": "test"}))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d-inactive", "juror": "@j1"}, system=True, parent="d"))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 2, {"dispute_id": "d-inactive", "juror": "@j2"}, system=True, parent="d"))
    apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "@j1", 2, {"dispute_id": "d-inactive"}))
    apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@j1", 3, {"dispute_id": "d-inactive", "vote": "yes", "resolution": {"summary": "restrict", "actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "@open", "restriction": "review"}}]}}))
    out = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 4, {"dispute_id": "d-inactive"}, system=True, parent="d"))
    assert out["applied"] == "DISPUTE_FINAL_RECEIPT"
    assert state["accounts"]["@j2"]["dispute_juror_eligible"] is False
    assert state["dispute_juror_accountability"]["by_juror"]["@j2"]["missed_vote_count"] == 1


def test_production_feed_ranking_uses_weighted_public_social_signals() -> None:
    state = {
        "accounts": {
            "@trusted": {"poh_tier": 2, "reputation": 50},
            "@low": {"poh_tier": 1, "reputation": 1},
            "@author": {"poh_tier": 2, "reputation": 20},
        },
        "content": {
            "posts": {
                "quality": {"post_id": "quality", "author": "@author", "visibility": "public", "created_nonce": 10, "reactions": {}},
                "brigaded": {"post_id": "brigaded", "author": "@low", "visibility": "public", "created_nonce": 20, "reactions": {}, "labels": ["brigading_suspected"]},
                "quiet-new": {"post_id": "quiet-new", "author": "@trusted", "visibility": "public", "created_nonce": 30, "reactions": {}},
            },
            "comments": {"c1": {"comment_id": "c1", "post_id": "quality", "visibility": "public"}},
            "reactions": {
                "@trusted:quality": {"by": "@trusted", "target_id": "quality", "reaction": "helpful"},
                "@trusted:quality:dupe": {"by": "@trusted", "target_id": "quality", "reaction": "love"},
                "@low:brigaded": {"by": "@low", "target_id": "brigaded", "reaction": "like"},
            },
            "media": {},
        },
    }
    with _client(state) as client:
        res = client.get("/v1/feed?rank=production&limit=2")
        assert res.status_code == 200, res.text
        body = res.json()
    ids = [item["post_id"] for item in body["items"]]
    assert ids[0] == "quality"
    assert "brigaded" not in ids[:1]
    assert body["ranking"]["production_social_feed"] is True
    assert body["ranking"]["uses_reputation_weighting"] is True
    assert body["ranking"]["uses_anti_brigading_caps"] is True
    quality = next(item for item in body["items"] if item["post_id"] == "quality")
    assert quality["feed_rank_breakdown"]["unique_reactors"] == 1


def test_generated_artifact_is_present_and_consistent() -> None:
    artifact = json.loads((ROOT / "generated" / "b528_b532_completion_proof_v1_5.json").read_text())
    assert artifact["ok"] is True
    assert artifact["feed_ranking"]["complete_for_deterministic_public_social_ranking"] is True
    assert artifact["feed_ranking"]["complete_for_personalized_recommendation"] is False
    assert artifact["validator_rehearsal"]["process_model"] == "subprocess_tcp_json_rpc"
    assert artifact["fresh_node_replay_sync"]["durable_db_used"] is True
