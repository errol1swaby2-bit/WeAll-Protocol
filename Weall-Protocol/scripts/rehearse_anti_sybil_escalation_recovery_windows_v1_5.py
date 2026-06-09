#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_anti_sybil_collusion_accountability_v1_5 import _env, _seed_case
from weall.runtime.apply.poh import apply_poh


def run_harness() -> dict[str, Any]:
    reviewers = ["@r1", "@r2", "@r3"]
    state: dict[str, Any] = {
        "height": 75,
        "accounts": {"@subject": {"poh_tier": 1}, "@challenger": {"poh_tier": 1}, **{r: {"poh_tier": 2} for r in reviewers}},
        "roles": {"poh_reviewers": {"active": {r: True for r in reviewers}}},
    }
    _seed_case(state, case_id="case-window", subject="@subject", reviewers=reviewers, commitment="sha256:" + "a" * 64)
    opened = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@challenger", 31, {"account_id": "@subject", "case_id": "case-window", "reason": "duplicate-human-suspected"}))
    resolved = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 32, {"challenge_id": opened["challenge_id"], "resolution": "upheld", "case_id": "case-window"}, system=True, parent="poh"))
    suspicion = next(iter(state.get("poh", {}).get("reviewer_collusion_suspicions", {}).get("by_case", {}).values()))
    retention_before = state.get("poh", {}).get("evidence_retention", {}).get("by_challenge", {}).get(opened["challenge_id"], {})
    # Advance height beyond the review window and complete a successful reverification/remedy path.
    state["height"] = int(suspicion.get("recovery_eligible_after_height") or 0) + 1
    _seed_case(state, case_id="case-window-reverified", subject="@subject", reviewers=reviewers, commitment="sha256:" + "b" * 64)
    retention_after = state.get("poh", {}).get("evidence_retention", {}).get("by_challenge", {}).get(opened["challenge_id"], {})
    return {
        "ok": bool(
            resolved.get("resolution") == "upheld"
            and suspicion.get("escalation_level") == "review_required"
            and int(suspicion.get("review_window_close_height") or 0) > int(suspicion.get("review_window_open_height") or 0)
            and int(suspicion.get("recovery_eligible_after_height") or 0) == int(suspicion.get("review_window_close_height") or 0)
            and retention_before.get("deletion_eligible") is False
            and retention_after.get("deletion_eligible") is True
        ),
        "batch": "565",
        "challenge_id": opened["challenge_id"],
        "suspicion_id": suspicion.get("suspicion_id"),
        "escalation_level": suspicion.get("escalation_level"),
        "review_window_open_height": suspicion.get("review_window_open_height"),
        "review_window_close_height": suspicion.get("review_window_close_height"),
        "recovery_eligible_after_height": suspicion.get("recovery_eligible_after_height"),
        "recovery_policy": suspicion.get("recovery_policy"),
        "reviewer_count": suspicion.get("reviewer_count"),
        "retention_before_recovery": retention_before,
        "retention_after_recovery": retention_after,
        "duplicate_human_detection_claimed": False,
        "collusion_adjudication_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
