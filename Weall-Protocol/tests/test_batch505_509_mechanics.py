from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.poh import apply_poh
from weall.runtime.poh.state import POH_STATUS_ACTIVE, canonical_account_poh_status, set_account_poh_status
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


def _env(tx_type: str, *, signer: str = "alice", nonce: int = 1, payload: dict | None = None, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="", system=system, parent=parent)


def _run_json(script: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), "--json"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return json.loads(proc.stdout)


def test_batch505_bft_adversarial_harness_catches_equivocation_and_partition_limits() -> None:
    out = _run_json("rehearse_bft_adversarial_v1_5.py")
    assert out["ok"] is True
    assert out["public_validator_enabled"] is False
    assert out["quorum_threshold"] == 3
    assert out["equivocation_detected"] is True
    assert out["partition"]["partition_a_can_finalize"] is False
    assert out["partition"]["partition_b_can_finalize"] is False
    assert len({row["validator_set_hash"] for row in out["restart_rows"]}) == 1
    assert len({row["leader"] for row in out["restart_rows"]}) == 1


def test_batch506_state_sync_adversarial_harness_rejects_bad_anchor_and_corruption() -> None:
    out = _run_json("rehearse_state_sync_adversarial_v1_5.py")
    assert out["ok"] is True
    assert out["good_snapshot_verified"] is True
    assert out["invalid_anchor_rejected"] is True
    assert out["corrupt_snapshot_rejected"] is True
    assert out["corrupt_snapshot_reason"] == "snapshot_hash_mismatch"
    assert out["stale_anchor_rejected"] is True


def test_batch507_reverification_completion_requires_fresh_successful_poh_finalize() -> None:
    state = {
        "height": 50,
        "accounts": {"alice": {"poh_tier": 2, "poh_status": "active"}},
        "roles": {"validators": {"active_set": ["juror-a", "juror-b", "juror-c"]}},
    }
    for account in ("alice", "juror-a", "juror-b", "juror-c"):
        state.setdefault("accounts", {}).setdefault(account, {})
        set_account_poh_status(state, account_id=account, poh_tier=2, status=POH_STATUS_ACTIVE, verified_at_height=1)

    apply_poh(state, _env("POH_CHALLENGE_OPEN", signer="bob", nonce=1, payload={"account_id": "alice", "reason": "duplicate"}))
    apply_poh(state, _env("POH_CHALLENGE_RESOLVE", signer="reviewer", nonce=2, payload={"challenge_id": "pohc:alice:1", "resolution": "upheld"}))
    assert state["poh"]["reverification"]["by_account"]["alice"]["status"] == "required"
    assert canonical_account_poh_status(state, "alice")["status"] == "revoked"

    # A fresh native async verification completes the pending reverification.
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", signer="alice", nonce=3, payload={"tier": 1}))
    case_id = "pohasync:alice:3"
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", signer="alice", nonce=4, payload={"case_id": case_id, "evidence_commitment": "c" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", signer="SYSTEM", nonce=5, system=True, parent="assign", payload={"case_id": case_id, "jurors": ["juror-a", "juror-b", "juror-c"]}))
    for i, juror in enumerate(("juror-a", "juror-b", "juror-c"), start=6):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", signer=juror, nonce=i, payload={"case_id": case_id}))
    for i, juror in enumerate(("juror-a", "juror-b", "juror-c"), start=9):
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", signer=juror, nonce=i, payload={"case_id": case_id, "verdict": "approve"}))
    state["height"] = 51
    res = apply_poh(state, _env("POH_ASYNC_FINALIZE", signer="SYSTEM", nonce=12, system=True, parent="finalize", payload={"case_id": case_id}))
    assert res["outcome"] == "approved"
    assert state["poh"]["reverification"]["by_account"]["alice"]["status"] == "completed"
    assert state["poh"]["reverification"]["by_account"]["alice"]["completed_by_case_id"] == case_id
    assert canonical_account_poh_status(state, "alice")["status"] == "active"


def test_batch508_appeal_panel_votes_derive_final_enforcement_decision() -> None:
    state = {
        "height": 70,
        "content": {"posts": {"post:alice:appeal": {"id": "post:alice:appeal", "author": "alice", "visibility": "public", "deleted": False, "labels": [], "locked": False}}, "comments": {}},
        "disputes_by_id": {
            "d-appeal-panel": {
                "dispute_id": "d-appeal-panel",
                "id": "d-appeal-panel",
                "stage": "appeal_review",
                "appeals": [{"by": "alice", "height": 69}],
                "assigned_jurors": ["juror-a", "juror-b", "juror-c"],
                "eligible_juror_ids": ["juror-a", "juror-b", "juror-c"],
                "required_votes": 2,
                "jurors": {
                    "juror-a": {"status": "accepted", "attendance": {"present": True}},
                    "juror-b": {"status": "accepted", "attendance": {"present": True}},
                    "juror-c": {"status": "accepted", "attendance": {"present": True}},
                },
                "resolution": {"summary": "remove", "actions": [{"tx_type": "CONTENT_VISIBILITY_SET", "payload": {"target_id": "post:alice:appeal", "visibility": "deleted"}}]},
            }
        },
    }
    res1 = apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", signer="juror-a", nonce=1, payload={"dispute_id": "d-appeal-panel", "appeal_decision": "reverse", "summary": "appeal accepted"}))
    assert res1["appeal_panel_result"]["reached"] is False
    res2 = apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", signer="juror-b", nonce=2, payload={"dispute_id": "d-appeal-panel", "appeal_decision": "reverse", "summary": "appeal accepted"}))
    assert res2["appeal_panel_result"]["reached"] is True
    assert state["disputes_by_id"]["d-appeal-panel"]["appeal_panel_result"]["decision"] == "reverse"

    final = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", signer="SYSTEM", nonce=3, system=True, parent="appeal-final", payload={"dispute_id": "d-appeal-panel"}))
    assert final["appeal_finalization"]["decision"] == "reverse"
    assert state["content"]["posts"]["post:alice:appeal"]["visibility"] == "public"
    assert state["disputes_by_id"]["d-appeal-panel"]["final_resolution"]["actions"] == []


def test_batch509_governance_execution_vector_pack_runs() -> None:
    out = _run_json("gen_governance_execution_vectors_v1_5.py")
    assert out["ok"] is True
    assert out["final_stage"] == "finalized"
    assert "GOV_EXECUTE" in out["emitted_h11"]
    assert "VALIDATOR_SUSPEND" in out["emitted_h12"]
    assert out["validator_b_status"] in {"pending_suspension", "suspended"}
    assert out["execution_receipt_count"] >= 1
    assert out["proposal_receipt_count"] >= 1


def test_batch505_509_generated_artifact_is_fresh_and_truth_bounded() -> None:
    path = ROOT / "generated" / "b505_b509_mechanics_proof_v1_5.json"
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["ok"] is True
    assert data["truth_boundaries"]["public_validators_enabled"] is False
    assert data["truth_boundaries"]["live_economics_enabled"] is False
    assert data["batches"]["505"]["ok"] is True
    assert data["batches"]["506"]["ok"] is True
    assert data["batches"]["509"]["ok"] is True
