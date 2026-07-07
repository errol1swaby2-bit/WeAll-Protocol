#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from weall.runtime.apply.poh import aggregate_poh_sybil_signals, select_poh_adjudication_panel, record_poh_collusion_adjudication, execute_poh_evidence_deletion


def run_harness() -> dict[str, Any]:
    state: dict[str, Any] = {
        "height": 900,
        "accounts": {
            "subject": {"nonce": 0, "poh_status": "active", "poh_tier": 2},
            "reviewer-a": {"nonce": 0, "poh_status": "active", "poh_tier": 2},
            "reviewer-b": {"nonce": 0, "poh_status": "active", "poh_tier": 2},
            "reviewer-c": {"nonce": 0, "poh_status": "active", "poh_tier": 2},
            "reviewer-d": {"nonce": 0, "poh_status": "active", "poh_tier": 2, "locked": True},
        },
        "poh": {
            "reviewer_history_scores": {
                "reviewer-c": {"reviewer_id": "reviewer-c", "eligible": True},
                "reviewer-d": {"reviewer_id": "reviewer-d", "eligible": True},
            },
            "reviewer_collusion_suspicions": {
                "by_case": {
                    "poh-reviewer-collusion:case-1:pohc:subject:1": {
                        "suspicion_id": "poh-reviewer-collusion:case-1:pohc:subject:1",
                        "challenge_id": "pohc:subject:1",
                        "case_id": "case-1",
                        "account_id": "subject",
                        "reviewers": ["reviewer-a", "reviewer-b", "reviewer-c"],
                        "status": "suspected_prior_approval_cluster",
                    }
                },
                "events": [],
            },
            "evidence_retention": {
                "by_challenge": {
                    "pohc:subject:1": {
                        "challenge_id": "pohc:subject:1",
                        "account_id": "subject",
                        "case_id": "case-1",
                        "status": "remedy_completed_minimal_retention",
                        "deletion_eligible": True,
                    }
                },
                "events": [],
            },
        },
    }
    signals = aggregate_poh_sybil_signals(
        state,
        subject_account="subject",
        signal_id="sybil-signal:subject:1",
        signals={
            "duplicate_evidence_commitments": ["ev-a", "ev-b"],
            "reviewer_overlap": ["reviewer-a", "reviewer-b", "reviewer-c"],
            "shared_device_hints": ["device-hint"],
            "challenge_history": ["pohc:subject:1"],
            "coordinated_review_windows": ["window-1", "window-2"],
        },
    )
    panel = select_poh_adjudication_panel(
        state,
        signal_id=signals["signal_id"],
        candidate_reviewers=["reviewer-a", "reviewer-b", "reviewer-c", "reviewer-d"],
        panel_size=3,
        seed="batch575",
    )
    adjudication = record_poh_collusion_adjudication(
        state,
        suspicion_id="poh-reviewer-collusion:case-1:pohc:subject:1",
        decision="confirmed",
        adjudicator_panel_id=panel["panel_id"],
    )
    deletion = execute_poh_evidence_deletion(state, challenge_id="pohc:subject:1", reason="adjudicated_and_remedy_completed")
    ok = bool(signals["requires_adjudication_panel"] and panel["selected_count"] == 3 and adjudication["status"] == "adjudicated_confirmed" and deletion["deleted"])
    return {
        "ok": ok,
        "batch": "575",
        "signal_aggregation": signals,
        "panel_selection": panel,
        "adjudication": adjudication,
        "evidence_deletion": deletion,
        "reviewer_scores": state["poh"].get("reviewer_history_scores", {}),
        "automatic_duplicate_human_detection_claimed": False,
        "automatic_collusion_detection_claimed": False,
    }


def main() -> int:
    argparse.ArgumentParser().parse_args(); print(json.dumps(run_harness(), sort_keys=True, indent=2)); return 0

if __name__ == "__main__":
    raise SystemExit(main())
