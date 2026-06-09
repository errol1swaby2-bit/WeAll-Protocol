#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.poh import apply_poh
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch547-accountability", payload=payload, sig="sig", system=system, parent=parent)


def _run_poh_accountability() -> dict[str, Any]:
    state: dict[str, Any] = {
        "height": 21,
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
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", "@subject", 1, {"case_id": "case-547", "account_id": "@subject", "evidence_commitment": "sha256:" + "d" * 64}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", "@subject", 2, {"case_id": "case-547", "evidence_id": "ev", "evidence_commitment": "sha256:" + "d" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 1, {"case_id": "case-547", "jurors": ["@reviewer", "@r2", "@r3"]}, system=True, parent="poh:case"))
    for i, reviewer in enumerate(["@reviewer", "@r2", "@r3"], start=1):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", reviewer, i, {"case_id": "case-547"}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", reviewer, i + 10, {"case_id": "case-547", "verdict": "approve"}))
    opened = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@r2", 30, {"account_id": "@subject", "case_id": "case-547", "reason": "duplicate-human-suspected"}))
    upheld = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 31, {"challenge_id": opened["challenge_id"], "resolution": "upheld", "case_id": "case-547"}, system=True, parent="poh:challenge"))
    dismissed_open = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@r3", 32, {"account_id": "@subject", "reason": "low-confidence"}))
    dismissed = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 33, {"challenge_id": dismissed_open["challenge_id"], "resolution": "dismissed"}, system=True, parent="poh:challenge"))
    reviewer = state["accounts"].get("@reviewer", {})
    rec = state.get("poh", {}).get("reviewer_accountability", {}).get("by_reviewer", {}).get("@reviewer", {})
    return {
        "ok": bool(reviewer.get("poh_reviewer_eligible") is False and rec.get("eligible_for_poh_review") is False and dismissed.get("consequence", {}).get("type") == "none"),
        "upheld_challenge_id": opened["challenge_id"],
        "dismissed_challenge_id": dismissed_open["challenge_id"],
        "upheld_resolution": upheld.get("resolution"),
        "dismissed_consequence": dismissed.get("consequence"),
        "reviewer_eligible_after_upheld_challenge": reviewer.get("poh_reviewer_eligible"),
        "reviewer_accountability_record": rec,
        "subject_status": state["accounts"].get("@subject", {}).get("poh_status"),
        "reverification_required": state.get("poh", {}).get("reverification", {}).get("by_account", {}).get("@subject", {}).get("status") == "required",
    }


def _run_dispute_accountability_and_remedy() -> dict[str, Any]:
    state: dict[str, Any] = {
        "height": 25,
        "accounts": {
            "@open": {"poh_tier": 2, "restricted": True, "locked": True, "latest_restriction": "review"},
            "@j1": {"poh_tier": 2},
            "@j2": {"poh_tier": 2},
            "SYSTEM": {"poh_tier": 0},
        },
        "roles": {"validators": {"active_set": ["@j1", "@j2"]}},
        "system_queue": [],
    }
    apply_dispute(state, _env("DISPUTE_OPEN", "@open", 1, {"dispute_id": "d-547", "target_type": "account", "target_id": "@open", "reason": "test"}))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d-547", "juror": "@j1"}, system=True, parent="d"))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 2, {"dispute_id": "d-547", "juror": "@j2"}, system=True, parent="d"))
    apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "@j1", 2, {"dispute_id": "d-547"}))
    apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@j1", 3, {"dispute_id": "d-547", "vote": "yes", "resolution": {"summary": "restrict", "actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "@open", "restriction": "review"}}]}}))
    first = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 4, {"dispute_id": "d-547"}, system=True, parent="d"))
    juror_ineligible = state["accounts"].get("@j2", {}).get("dispute_juror_eligible") is False
    # Reopen the appeal state explicitly for a remedy receipt; this mirrors a
    # governance/appeal remedy after a false positive or missed-juror review.
    d = state["disputes_by_id"]["d-547"]
    d["stage"] = "appealed"
    d["appeals"] = [{"by": "@open", "reason": "false-positive-remedy"}]
    remedy = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 5, {"dispute_id": "d-547", "appeal_resolution": {"decision": "modify", "summary": "remedy", "actions": [{"tx_type": "ACCOUNT_REINSTATE", "payload": {"account_id": "@open"}}, {"tx_type": "ROLE_ELIGIBILITY_SET", "payload": {"account_id": "@j2", "role": "dispute_juror", "eligible": True}}]}}, system=True, parent="d"))
    target = state["accounts"].get("@open", {})
    juror = state["accounts"].get("@j2", {})
    return {
        "ok": bool(juror_ineligible and target.get("restricted") is False and target.get("locked") is False and juror.get("dispute_juror_eligible") is True),
        "first_final_receipt": first,
        "remedy_receipt": remedy,
        "juror_ineligible_after_missed_vote": juror_ineligible,
        "juror_eligible_after_remedy": juror.get("dispute_juror_eligible"),
        "target_reinstated": target.get("restricted") is False and target.get("locked") is False,
        "juror_accountability_record": state.get("dispute_juror_accountability", {}).get("by_juror", {}).get("@j2", {}),
        "target_remedies": target.get("remedies") or [],
    }


def run_harness() -> dict[str, Any]:
    poh = _run_poh_accountability()
    dispute = _run_dispute_accountability_and_remedy()
    return {
        "ok": bool(poh.get("ok") and dispute.get("ok")),
        "batch": "547",
        "poh_reviewer_accountability": poh,
        "dispute_juror_accountability_and_remedy": dispute,
        "false_positive_remedy_path_present": bool(dispute.get("target_reinstated") and dispute.get("juror_eligible_after_remedy")),
        "collusion_detection_claimed": False,
        "duplicate_human_detection_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
