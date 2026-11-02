#!/usr/bin/env python3
"""Make a read-only, source-bound packet for the 15 stale V2 TX reviews.

This report makes no approvals and does not replace historical replay,
independent semantic review, or the V2 spec compiler's fail-closed gate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import audit_v2_semantic_review_drift as audit
import v2_spec_validation as validation

ROOT = Path(__file__).resolve().parents[1]
KNOWN_STALE = frozenset(
    {
        "DISPUTE_OPEN",
        "DISPUTE_VOTE_SUBMIT",
        "DISPUTE_RESOLVE",
        "DISPUTE_APPEAL",
        "DISPUTE_FINAL_RECEIPT",
        "ACCOUNT_BAN",
        "ROLE_JUROR_ENROLL",
        "ROLE_JUROR_ACTIVATE",
        "ROLE_JUROR_REINSTATE",
        "ROLE_VALIDATOR_ACTIVATE",
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "ROLE_EMISSARY_SEAT",
        "ROLE_GOV_EXECUTOR_SET",
        "REVIEWER_LANE_OPT_IN",
        "REVIEWER_LANE_OPT_OUT",
    }
)


def field_differences(previous: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    """Preserve precise reviewed material, including missing-vs-null distinctions."""
    changes = []
    for key in sorted(previous.keys() | current.keys()):
        old_present = key in previous
        new_present = key in current
        if old_present and new_present and previous[key] == current[key]:
            continue
        changes.append(
            {
                "field": key,
                "previous_present": old_present,
                "current_present": new_present,
                "previous": previous[key] if old_present else None,
                "current": current[key] if new_present else None,
            }
        )
    return changes


def build_packet() -> dict[str, Any]:
    current_rows, stable_ids, sources = audit._current_rows()
    prior_rows, prior_shape = audit._prior_rows()
    review_source = json.loads(
        (ROOT / "specs/v2/source/semantic_reviews.json").read_text(encoding="utf-8")
    )
    reviews = {
        str(row["tx_type"]): row
        for row in review_source["transactions"]
        if isinstance(row, dict)
    }
    previous = {str(row["tx_type"]): row for row in prior_rows}
    if len(current_rows) != 236 or len(reviews) != 236 or len(previous) != 236:
        raise ValueError("v2_review_packet_requires_exactly_236_unique_rows")
    if (
        len({str(row["tx_type"]) for row in current_rows}) != 236
        or len({str(row["tx_type"]) for row in review_source["transactions"]}) != 236
    ):
        raise ValueError("v2_review_packet_has_duplicate_tx_type")

    missing_stable_ids = audit._missing_state_ids(current_rows, stable_ids, sources)
    pending = []
    for row in sorted(current_rows, key=lambda item: str(item["tx_type"])):
        tx_type = str(row["tx_type"])
        if tx_type not in reviews or tx_type not in previous:
            raise ValueError(f"v2_review_packet_missing_review_or_baseline:{tx_type}")
        review = reviews[tx_type]
        accepted_digest = str(review.get("review_digest") or "")
        current_material = validation.tx_review_material(row)
        current_digest = validation.compact_digest(current_material)
        if current_digest == accepted_digest:
            continue
        old_material = validation.tx_review_material(previous[tx_type])
        old_digest = validation.compact_digest(old_material)
        diffs = field_differences(old_material, current_material)
        if tx_type == "DISPUTE_OPEN":
            review_lane = "handler_source_attribution_and_derived_contract"
        elif tx_type == "ACCOUNT_BAN":
            review_lane = "account_sanction_authority_and_finality"
        elif tx_type.startswith("DISPUTE_"):
            review_lane = "dispute_ballot_or_appeal_semantics"
        else:
            review_lane = "versioned_role_and_reviewer_eligibility"
        pending.append(
            {
                "tx_type": tx_type,
                "stable_id": row["stable_id"],
                "review_lane": review_lane,
                "accepted_review_digest": accepted_digest,
                "archived_compiled_material_digest": old_digest,
                "current_material_digest": current_digest,
                "archive_matches_accepted_digest": old_digest == accepted_digest,
                "archived_implementation_source": old_material.get("implementation_source"),
                "current_implementation_source": current_material.get("implementation_source"),
                "changed_fields": diffs,
                "changed_field_names": [item["field"] for item in diffs],
                "current_material_has_unexplained_delta": not bool(diffs),
                "reviewer_on_record": review.get("reviewer"),
                "reviewed_at_on_record": review.get("reviewed_at"),
                "independent_review_on_record": review.get("independent_review"),
                "signed_off_for_current_digest": False,
                "historical_replay_proven": False,
                "classification_not_semantic_approval": True,
            }
        )
    unexpected = sorted({item["tx_type"] for item in pending} - KNOWN_STALE)
    return {
        "schema": "weall.pr77.v2_semantic_review_decision_packet.v1",
        "kind": "read_only_implementation_comparison",
        "previous_generated_shape": prior_shape,
        "registered_transaction_count": len(current_rows),
        "pending_count": len(pending),
        "newly_stale_not_in_known_15": unexpected,
        "known_stale_now_resolved": sorted(
            KNOWN_STALE - {item["tx_type"] for item in pending}
        ),
        "missing_state_stable_ids": missing_stable_ids,
        "independent_human_approval_recorded_by_this_packet": False,
        "production_or_testnet_authority": False,
        "historical_compatibility_proven": False,
        "must_not_update_semantic_reviews_automatically": True,
        "transactions": pending,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    path: Path = args.report
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise SystemExit("report_destination_must_be_new_regular_file")
    packet = build_packet()
    with path.open("x", encoding="utf-8") as output:
        json.dump(packet, output, sort_keys=True, indent=2)
        output.write("\n")
    print(
        json.dumps(
            {
                "pending_count": packet["pending_count"],
                "newly_stale_not_in_known_15": packet["newly_stale_not_in_known_15"],
                "known_stale_now_resolved": packet["known_stale_now_resolved"],
                "missing_state_stable_ids": packet["missing_state_stable_ids"],
                "review_material_archive_does_not_match_prior_approval": [
                    item["tx_type"]
                    for item in packet["transactions"]
                    if not item["archive_matches_accepted_digest"]
                ],
                "changed_fields_by_tx": {
                    item["tx_type"]: item["changed_field_names"]
                    for item in packet["transactions"]
                },
                "approvals_modified": False,
            },
            sort_keys=True,
            indent=2,
        )
    )
    if packet["newly_stale_not_in_known_15"] or packet["missing_state_stable_ids"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
