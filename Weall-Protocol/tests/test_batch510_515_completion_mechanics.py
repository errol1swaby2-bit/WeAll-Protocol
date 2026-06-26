from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.storage import apply_storage
from weall.runtime.poh.state import POH_STATUS_ACTIVE, canonical_account_poh_status, set_account_poh_status
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]
CID_A = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"


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


def test_batch510_controlled_validator_network_completion_harness() -> None:
    out = _run_json("rehearse_controlled_validator_network_completion_v1_5.py")
    assert out["ok"] is True
    assert out["public_validator_enabled"] is False
    assert out["quorum_finalize_result"] == "finalized"
    assert out["minority_partition_finalize_result"] == "finality_threshold_not_met"
    assert "validator-e" in out["candidate_join"]["active_after_join"]
    assert "validator-a" not in out["slash_accountability"]["active_after_slash"]
    assert len(set(out["restart_roots"])) == 1


def test_batch510_fresh_node_sync_completion_harness() -> None:
    out = _run_json("rehearse_fresh_node_sync_completion_v1_5.py")
    assert out["ok"] is True
    assert out["verified"] is True
    assert out["source_height"] == out["fresh_height"] == 42
    assert out["source_state_root"] == out["fresh_state_root"]


def test_batch511_poh_reverification_marks_challenge_reverified() -> None:
    state = {"height": 10, "accounts": {"alice": {"poh_tier": 2}, "juror-a": {}, "juror-b": {}, "juror-c": {}}, "roles": {"validators": {"active_set": ["juror-a", "juror-b", "juror-c"]}}}
    for acct in ("alice", "juror-a", "juror-b", "juror-c"):
        set_account_poh_status(state, account_id=acct, poh_tier=2, status=POH_STATUS_ACTIVE, verified_at_height=1)

    apply_poh(state, _env("POH_CHALLENGE_OPEN", signer="bob", nonce=1, payload={"account_id": "alice", "reason": "duplicate"}))
    apply_poh(state, _env("POH_CHALLENGE_RESOLVE", signer="reviewer", nonce=2, payload={"challenge_id": "pohc:alice:1", "resolution": "upheld"}))
    assert canonical_account_poh_status(state, "alice")["status"] == "revoked"

    case_id = "pohasync:alice:3"
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", signer="alice", nonce=3, payload={"tier": 1}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", signer="alice", nonce=4, payload={"case_id": case_id, "evidence_commitment": "b" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", signer="SYSTEM", system=True, parent="assign", nonce=5, payload={"case_id": case_id, "jurors": ["juror-a", "juror-b", "juror-c"]}))
    for i, juror in enumerate(("juror-a", "juror-b", "juror-c"), start=6):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", signer=juror, nonce=i, payload={"case_id": case_id}))
    for i, juror in enumerate(("juror-a", "juror-b", "juror-c"), start=9):
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", signer=juror, nonce=i, payload={"case_id": case_id, "verdict": "approve"}))
    state["height"] = 11
    apply_poh(state, _env("POH_ASYNC_FINALIZE", signer="SYSTEM", system=True, parent="final", nonce=12, payload={"case_id": case_id}))

    ch = state["poh"]["challenges"]["pohc:alice:1"]
    assert ch["status"] == "resolved_reverified"
    assert ch["post_challenge_reverification"]["case_id"] == case_id
    assert canonical_account_poh_status(state, "alice")["status"] == "active"


def test_batch511_dispute_final_receipt_applies_account_restriction() -> None:
    state = {
        "height": 8,
        "accounts": {"mallory": {}},
        "disputes_by_id": {
            "d-account": {
                "dispute_id": "d-account",
                "id": "d-account",
                "stage": "appeal_review",
                "appeals": [{"by": "mallory", "height": 7}],
                "resolution": {
                    "summary": "account abuse upheld",
                    "actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "mallory", "restriction": "posting_limited", "reason": "abuse_upheld"}}],
                },
                "appeal_panel_result": {"reached": True, "decision": "uphold", "resolution": {"decision": "uphold"}},
            }
        },
    }
    out = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", signer="SYSTEM", system=True, parent="d-account", nonce=9, payload={"dispute_id": "d-account"}))
    assert out["appeal_finalization"]["decision"] == "uphold"
    assert out["enforcement_applied"][0]["tx_type"] == "ACCOUNT_RESTRICTION_SET"
    assert state["accounts"]["mallory"]["restricted"] is True
    assert state["accounts"]["mallory"]["latest_restriction"] == "posting_limited"


def test_batch512_governance_execution_records_deterministic_audit_hash() -> None:
    state = {
        "height": 20,
        "gov_proposals_by_id": {
            "gp-audit": {
                "proposal_id": "gp-audit",
                "stage": "tallied",
                "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_percent": 67}}],
                "tallies": [{"height": 19, "payload": {"passed": True}}],
            }
        },
    }
    out = apply_governance(state, _env("GOV_EXECUTE", signer="SYSTEM", system=True, parent="gp-audit", nonce=21, payload={"proposal_id": "gp-audit"}))
    assert out == {"applied": True, "proposal_id": "gp-audit"}
    audit = state["governance_execution_audit"][-1]
    execution = state["gov_proposals_by_id"]["gp-audit"]["executions"][-1]
    assert audit["execution_hash"]
    assert audit["emitted_actions"][0]["tx_type"] == "GOV_QUORUM_SET"
    assert execution["execution_hash"] == audit["execution_hash"]


def test_batch513_storage_pin_failure_reassigns_to_spare_target() -> None:
    state = {
        "height": 5,
        "params": {"ipfs_replication_factor": 2},
        "storage": {"operators": {"op-a": {"enabled": True}, "op-b": {"enabled": True}, "op-c": {"enabled": True}}},
    }
    pin = apply_storage(state, _env("IPFS_PIN_REQUEST", signer="alice", nonce=1, payload={"pin_id": "pin-complete", "cid": CID_A, "size_bytes": 0}))
    targets = list(pin["targets"])
    assert len(targets) == 2
    failed = targets[0]
    out = apply_storage(state, _env("IPFS_PIN_CONFIRM", signer="SYSTEM", system=True, parent="pin-complete", nonce=2, payload={"pin_id": "pin-complete", "cid": CID_A, "operator_id": failed, "ok": False}))
    rec = state["storage"]["pins"]["pin-complete"]
    assert out["reassignment"]["reassigned"] is True
    assert failed not in rec["targets"]
    assert len(rec["targets"]) == 2
    assert rec["durability_status"] == "reassignment_pending_confirmation"


def test_batch515_completion_artifact_runs_and_preserves_locked_boundaries() -> None:
    out = _run_json("gen_b510_b515_completion_proof_v1_5.py")
    assert out["ok"] is True
    assert out["truth_boundaries"]["public_validators_enabled"] is False
    assert out["truth_boundaries"]["live_economics_enabled"] is False
    assert out["truth_boundaries"]["automatic_protocol_upgrades_enabled"] is False
    assert out["truth_boundaries"]["production_helper_execution_enabled"] is False
    assert out["batches"]["510"]["ok"] is True
    assert out["batches"]["511"]["ok"] is True
    assert out["batches"]["512"]["ok"] is True
    assert out["batches"]["513"]["ok"] is True
    assert out["batches"]["514"]["ok"] is True
