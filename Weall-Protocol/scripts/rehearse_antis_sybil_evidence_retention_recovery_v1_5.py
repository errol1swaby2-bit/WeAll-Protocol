#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from weall.runtime.apply.poh import apply_poh
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch552-retention", payload=payload, sig="sig", system=system, parent=parent)


def _seed_case(state: dict[str, Any], case_id: str, account: str) -> None:
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", account, 1, {"case_id": case_id, "account_id": account, "evidence_commitment": "sha256:" + "c" * 64}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", account, 2, {"case_id": case_id, "evidence_id": "ev-" + case_id, "evidence_commitment": "sha256:" + "c" * 64}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 1, {"case_id": case_id, "jurors": ["@reviewer", "@juror", "@r2"]}, system=True, parent="poh"))
    for idx, reviewer in enumerate(["@reviewer", "@juror", "@r2"], start=1):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", reviewer, 10 + idx, {"case_id": case_id}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", reviewer, 20 + idx, {"case_id": case_id, "verdict": "approve"}))
    apply_poh(state, _env("POH_ASYNC_FINALIZE", "SYSTEM", 2, {"case_id": case_id}, system=True, parent="poh"))


def run_harness() -> dict[str, Any]:
    state: dict[str, Any] = {
        "height": 12,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 1, "reputation": 10},
            "@bob": {"nonce": 0, "poh_tier": 1, "reputation": 3},
            "@reviewer": {"nonce": 0, "poh_tier": 2, "reputation": 7},
            "@juror": {"nonce": 0, "poh_tier": 2, "reputation": 7},
            "@r2": {"nonce": 0, "poh_tier": 2, "reputation": 7},
        },
        "roles": {"poh_reviewers": {"active": {"@reviewer": True, "@juror": True, "@r2": True}}},
    }
    _seed_case(state, "case-a", "@alice")
    opened = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@bob", 2, {"account_id": "@alice", "case_id": "case-a", "reason": "duplicate-human"}))
    resolved = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 3, {"challenge_id": opened["challenge_id"], "resolution": "upheld", "case_id": "case-a"}, system=True, parent="challenge"))
    retention_before = state.get("poh", {}).get("evidence_retention", {}).get("by_challenge", {}).get(opened["challenge_id"], {})
    _seed_case(state, "case-r", "@alice")
    retention_after = state.get("poh", {}).get("evidence_retention", {}).get("by_challenge", {}).get(opened["challenge_id"], {})
    return {
        "ok": bool(retention_before.get("status") == "retain_until_reverification_or_appeal" and retention_after.get("status") == "remedy_completed_minimal_retention"),
        "batch": "552",
        "challenge_id": opened["challenge_id"],
        "resolution": resolved.get("resolution"),
        "subject_status_after_upheld": state.get("poh_status", {}).get("by_account", {}).get("@alice", {}).get("status"),
        "retention_before_reverification": retention_before,
        "retention_after_reverification": retention_after,
        "reverification_status": state.get("poh", {}).get("reverification", {}).get("by_account", {}).get("@alice", {}).get("status"),
        "reviewer_accountability_recorded": bool(state.get("poh", {}).get("reviewer_accountability", {}).get("by_reviewer")),
        "duplicate_human_detection_claimed": False,
        "collusion_detection_claimed": False,
        "false_positive_recovery_path_present": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
