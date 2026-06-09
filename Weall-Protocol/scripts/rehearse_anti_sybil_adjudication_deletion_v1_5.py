#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import copy
from typing import Any

from rehearse_anti_sybil_collusion_accountability_v1_5 import _env, _seed_case
from weall.runtime.apply.poh import apply_poh, execute_poh_evidence_deletion, record_poh_collusion_adjudication


def run_harness() -> dict[str, Any]:
    reviewers = ["@r1", "@r2", "@r3"]
    state: dict[str, Any] = {
        "height": 120,
        "accounts": {"@subject": {"poh_tier": 1}, "@challenger": {"poh_tier": 2}, **{r: {"poh_tier": 2} for r in reviewers}},
        "roles": {"poh_reviewers": {"active": {r: True for r in reviewers}}},
    }
    _seed_case(state, case_id="case-adjudicate", subject="@subject", reviewers=reviewers, commitment="sha256:" + "c" * 64)
    opened = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@challenger", 61, {"account_id": "@subject", "case_id": "case-adjudicate", "reason": "duplicate-human-suspected"}))
    resolved = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 62, {"challenge_id": opened["challenge_id"], "resolution": "upheld", "case_id": "case-adjudicate"}, system=True, parent="poh"))
    suspicion = next(iter(state.get("poh", {}).get("reviewer_collusion_suspicions", {}).get("by_case", {}).values()))
    confirmed = record_poh_collusion_adjudication(state, suspicion_id=suspicion["suspicion_id"], decision="confirmed", adjudicator_panel_id="panel:anti-sybil:1")
    scores_after_confirm = copy.deepcopy(state.get("poh", {}).get("reviewer_history_scores", {}))
    # A false-positive remedy can dismiss the same suspicion later and recover reviewers.
    state["height"] = 5000
    dismissed = record_poh_collusion_adjudication(state, suspicion_id=suspicion["suspicion_id"], decision="dismissed", adjudicator_panel_id="panel:appeal:1", note="false_positive_remedy")
    scores_after_dismiss = copy.deepcopy(state.get("poh", {}).get("reviewer_history_scores", {}))
    # Complete reverification/remedy and execute deletion of eligible raw evidence.
    retention = state["poh"]["evidence_retention"]["by_challenge"][opened["challenge_id"]]
    retention["status"] = "remedy_completed_minimal_retention"
    retention["deletion_eligible"] = True
    deletion = execute_poh_evidence_deletion(state, challenge_id=opened["challenge_id"], reason="false_positive_remedy_completed")
    final_retention = state["poh"]["evidence_retention"]["by_challenge"][opened["challenge_id"]]
    return {
        "ok": bool(resolved.get("resolution") == "upheld" and confirmed.get("status") == "adjudicated_confirmed" and dismissed.get("status") == "adjudicated_dismissed" and deletion.get("deleted") is True and all(scores_after_dismiss[r]["eligible"] for r in reviewers)),
        "batch": "570",
        "challenge_id": opened["challenge_id"],
        "suspicion_id": suspicion["suspicion_id"],
        "confirmed_adjudication": confirmed,
        "dismissed_adjudication": dismissed,
        "scores_after_confirm": scores_after_confirm,
        "scores_after_dismiss": scores_after_dismiss,
        "evidence_deletion": deletion,
        "final_retention_record": final_retention,
        "false_positive_compensation_policy": "eligibility_reinstatement_and_minimal_retention_deletion",
        "duplicate_human_detection_claimed": False,
        "automatic_collusion_detection_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
