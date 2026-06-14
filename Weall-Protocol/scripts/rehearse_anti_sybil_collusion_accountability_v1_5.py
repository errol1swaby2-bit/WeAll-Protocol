#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.roles import apply_roles
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch559-anti-sybil", payload=payload, sig="sig", system=system, parent=parent)


def _ensure_poh_async_reviewers(state: dict[str, Any], reviewers: list[str]) -> None:
    """Seed explicit Batch 616 reviewer-lane consent for legacy anti-sybil harnesses.

    The production consent model no longer treats Tier-2 or coarse juror enrollment
    as permission to perform PoH async review work.  These historical rehearsal
    scripts are still valid readiness evidence, but they must now model the same
    explicit lane opt-in that a real reviewer would perform before assignment.
    """
    for idx, reviewer in enumerate(reviewers, start=1):
        apply_roles(
            state,
            _env(
                "REVIEWER_LANE_OPT_IN",
                reviewer,
                1000 + idx,
                {"account_id": reviewer, "lane": "poh_async_review"},
            ),
        )


def _seed_case(state: dict[str, Any], *, case_id: str, subject: str, reviewers: list[str], commitment: str) -> None:
    _ensure_poh_async_reviewers(state, reviewers)
    apply_poh(state, _env("POH_ASYNC_REQUEST_OPEN", subject, 1, {"case_id": case_id, "account_id": subject, "evidence_commitment": commitment}))
    apply_poh(state, _env("POH_ASYNC_EVIDENCE_DECLARE", subject, 2, {"case_id": case_id, "evidence_id": "ev-" + case_id, "evidence_commitment": commitment}))
    apply_poh(state, _env("POH_ASYNC_JUROR_ASSIGN", "SYSTEM", 1, {"case_id": case_id, "jurors": reviewers}, system=True, parent="poh"))
    for idx, reviewer in enumerate(reviewers, start=1):
        apply_poh(state, _env("POH_ASYNC_JUROR_ACCEPT", reviewer, 10 + idx, {"case_id": case_id}))
        apply_poh(state, _env("POH_ASYNC_REVIEW_SUBMIT", reviewer, 20 + idx, {"case_id": case_id, "verdict": "approve"}))
    apply_poh(state, _env("POH_ASYNC_FINALIZE", "SYSTEM", 2, {"case_id": case_id}, system=True, parent="poh"))


def run_harness() -> dict[str, Any]:
    reviewers = ["@r1", "@r2", "@r3"]
    commitment = "sha256:" + "e" * 64
    state: dict[str, Any] = {
        "height": 50,
        "accounts": {"@subject": {"poh_tier": 1}, "@challenger": {"poh_tier": 1}, **{r: {"poh_tier": 2} for r in reviewers}},
        "roles": {"poh_reviewers": {"active": {r: True for r in reviewers}}},
    }
    _seed_case(state, case_id="case-collusion", subject="@subject", reviewers=reviewers, commitment=commitment)
    opened = apply_poh(state, _env("POH_CHALLENGE_OPEN", "@challenger", 7, {"account_id": "@subject", "case_id": "case-collusion", "reason": "duplicate-human-suspected"}))
    resolved = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 8, {"challenge_id": opened["challenge_id"], "resolution": "upheld", "case_id": "case-collusion"}, system=True, parent="poh"))
    suspicion_root = state.get("poh", {}).get("reviewer_collusion_suspicions", {})
    suspicions = suspicion_root.get("by_case", {}) if isinstance(suspicion_root, dict) else {}
    suspicion = next(iter(suspicions.values()), {}) if isinstance(suspicions, dict) and suspicions else {}
    # Reverification/remedy closes the evidence-retention loop without claiming
    # duplicate-human detection or collusion adjudication is solved.
    _seed_case(state, case_id="case-reverified", subject="@subject", reviewers=reviewers, commitment="sha256:" + "f" * 64)
    retention = state.get("poh", {}).get("evidence_retention", {}).get("by_challenge", {}).get(opened["challenge_id"], {})
    return {
        "ok": bool(resolved.get("resolution") == "upheld" and suspicion.get("requires_followup_review") is True and retention.get("deletion_eligible") is True),
        "batch": "559",
        "challenge_id": opened["challenge_id"],
        "reviewer_count_flagged": len(resolved.get("consequence", {}).get("reviewer_accountability", {}).get("reviewers") or []),
        "reviewer_collusion_suspicion_recorded": bool(suspicion),
        "reviewer_collusion_suspicion": suspicion,
        "evidence_retention_after_recovery": retention,
        "reverification_status": state.get("poh", {}).get("reverification", {}).get("by_account", {}).get("@subject", {}).get("status"),
        "duplicate_human_suspicion_recorded": True,
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
