#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

from weall.runtime.apply.poh import (
    aggregate_poh_sybil_signals,
    execute_poh_evidence_deletion,
    record_poh_adjudication_appeal,
    record_poh_collusion_adjudication,
    select_poh_adjudication_panel_conflict_aware,
)

Json = dict[str, Any]


def run_harness() -> Json:
    state: Json = {
        "height": 900,
        "accounts": {f"reviewer-{c}": {"poh_tier": 2} for c in "abcdefg"} | {"subject": {"poh_tier": 2}},
        "poh": {
            "reviewer_collusion_suspicions": {
                "by_case": {
                    "poh-reviewer-collusion:case:challenge": {
                        "suspicion_id": "poh-reviewer-collusion:case:challenge",
                        "challenge_id": "challenge",
                        "case_id": "case",
                        "account_id": "subject",
                        "reviewers": ["reviewer-a", "reviewer-b", "reviewer-c"],
                        "reviewer_count": 3,
                        "status": "suspected_prior_approval_cluster",
                    }
                },
                "events": [],
            },
            "evidence_retention": {
                "by_challenge": {
                    "challenge": {
                        "challenge_id": "challenge",
                        "account_id": "subject",
                        "case_id": "case",
                        "status": "remedy_completed_minimal_retention",
                        "deletion_eligible": True,
                    }
                },
                "events": [],
            },
            "reviewer_history_scores": {
                "reviewer-a": {"reviewer_id": "reviewer-a", "eligible": False, "confirmed_collusion_count": 1, "suspended_until_height": 5000},
                "reviewer-b": {"reviewer_id": "reviewer-b", "eligible": True},
                "reviewer-c": {"reviewer_id": "reviewer-c", "eligible": True},
            },
        },
        "roles": {"poh_reviewers": {"active": {"reviewer-a": False}, "suspended": {"reviewer-a": {"reason": "test"}}}},
    }
    signals = aggregate_poh_sybil_signals(
        state,
        subject_account="subject",
        signal_id="signal:subject",
        signals={
            "duplicate_evidence_commitments": ["e1", "e2"],
            "reviewer_overlap": ["reviewer-a", "reviewer-b", "reviewer-c"],
            "shared_device_hints": ["device-1", "device-2"],
            "challenge_history": ["challenge"],
            "coordinated_review_windows": ["w1"],
        },
    )
    panel = select_poh_adjudication_panel_conflict_aware(
        state,
        signal_id="signal:subject",
        candidate_reviewers=["reviewer-a", "reviewer-b", "reviewer-c", "reviewer-d", "reviewer-e", "reviewer-f", "reviewer-g"],
        excluded_reviewers=["reviewer-a", "reviewer-b", "reviewer-c"],
        panel_size=3,
        seed="batch580",
    )
    confirmed = record_poh_collusion_adjudication(
        state,
        suspicion_id="poh-reviewer-collusion:case:challenge",
        decision="confirmed",
        adjudicator_panel_id=panel["panel_id"],
        note="conflict-free panel confirmed prior-reviewer misconduct",
    )
    appeal = record_poh_adjudication_appeal(
        state,
        signal_id="signal:subject",
        panel_id=panel["panel_id"],
        appellant="reviewer-a",
        decision="remedy_granted",
        reason="new exculpatory evidence accepted",
    )
    deletion = execute_poh_evidence_deletion(state, challenge_id="challenge", reason="appeal_remedy_and_retention_completed")
    selected = set(panel.get("selected_reviewers", []))
    excluded = set(panel.get("excluded_reviewers", []))
    return {
        "ok": signals["requires_adjudication_panel"] is True and panel["conflict_free_panel"] is True and confirmed["status"] == "adjudicated_confirmed" and appeal["recovery_applied"] is True and deletion["deleted"] is True,
        "signal_aggregation": signals,
        "panel_selection": panel,
        "conflict_exclusion_worked": selected.isdisjoint(excluded),
        "adjudication": confirmed,
        "appeal": appeal,
        "evidence_deletion": deletion,
        "automatic_duplicate_human_detection_claimed": False,
        "automatic_collusion_detection_claimed": False,
    }

if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
