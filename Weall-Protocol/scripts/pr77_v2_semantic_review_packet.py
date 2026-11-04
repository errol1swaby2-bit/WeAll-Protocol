#!/usr/bin/env python3
"""Make a read-only, source-bound packet for stale V2 TX reviews.

This report makes no approvals and does not replace historical replay,
independent semantic review, or the V2 spec compiler's fail-closed gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import audit_v2_semantic_review_drift as audit  # noqa: E402
import v2_spec_validation as validation  # noqa: E402

KNOWN_STALE = frozenset(
    {
        "DISPUTE_OPEN",
        "DISPUTE_JUROR_ASSIGN",
        "DISPUTE_JUROR_ACCEPT",
        "DISPUTE_VOTE_SUBMIT",
        "DISPUTE_RESOLVE",
        "DISPUTE_APPEAL",
        "DISPUTE_FINAL_RECEIPT",
        "CONTENT_FLAG",
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


def failure_code_deltas(previous: Any, current: Any) -> dict[str, list[dict[str, str]]]:
    """Show exact code/reason additions and removals without interpreting them."""

    def pairs(value: Any) -> set[tuple[str, str]]:
        if not isinstance(value, list):
            raise ValueError("v2_review_packet_failure_codes_not_list")
        out: set[tuple[str, str]] = set()
        for row in value:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("code"), str)
                or not isinstance(row.get("reason"), str)
            ):
                raise ValueError("v2_review_packet_failure_code_invalid_shape")
            out.add((row["code"], row["reason"]))
        return out

    old = pairs(previous)
    new = pairs(current)

    def records(values: set[tuple[str, str]]) -> list[dict[str, str]]:
        return [{"code": code, "reason": reason} for code, reason in sorted(values)]

    return {"added": records(new - old), "removed": records(old - new)}


def packet_integrity_blockers(packet: dict[str, Any]) -> list[str]:
    """Fail closed on omitted or forged review rows, never grant approval.

    This is a source-bound review diagnostic, not an authority ledger. In this
    frozen candidate inventory, *all* 18 known stale rows must remain visible.
    A changed inventory requires an explicit, independently reviewed update,
    not silently dropping a row or accepting an empty packet.
    """
    rows = packet.get("transactions")
    if not isinstance(rows, list):
        return ["transactions_not_list"]

    blockers: list[str] = []
    if packet.get("schema") != "weall.pr77.v2_semantic_review_decision_packet.v2":
        blockers.append("review_packet_schema_mismatch")
    if packet.get("registered_transaction_count") != 236:
        blockers.append("registered_transaction_count_changed")
    if packet.get("pending_count") != len(rows) or len(rows) != len(KNOWN_STALE):
        blockers.append("pending_count_mismatch")

    names = [
        row.get("tx_type") if isinstance(row, dict) else None
        for row in rows
    ]
    valid_names = [
        name for name in names if isinstance(name, str) and name.strip()
    ]
    present = set(valid_names)
    if len(valid_names) != len(rows):
        blockers.append("invalid_pending_transaction_identity")
    if len(present) != len(valid_names):
        blockers.append("duplicate_pending_transaction")
    if present != KNOWN_STALE:
        blockers.append("stale_inventory_mismatch")
    if packet.get("newly_stale_not_in_known_inventory"):
        blockers.append("unexpected_stale_transaction")
    if packet.get("known_stale_now_resolved") != sorted(KNOWN_STALE - present):
        blockers.append("resolved_inventory_claim_mismatch")
    if packet.get("known_stale_now_resolved"):
        blockers.append("unreviewed_inventory_resolution")
    if packet.get("missing_state_stable_ids"):
        blockers.append("missing_state_stable_ids")

    stable_ids = [
        row.get("stable_id") if isinstance(row, dict) else None
        for row in rows
    ]
    if any(not isinstance(sid, str) or not sid.strip() for sid in stable_ids):
        blockers.append("invalid_pending_stable_id")
    if len({sid for sid in stable_ids if isinstance(sid, str)}) != len(rows):
        blockers.append("duplicate_pending_stable_id")

    for row in rows:
        if not isinstance(row, dict):
            blockers.append("invalid_pending_transaction_row")
            continue
        tx_type = str(row.get("tx_type") or "")
        if not isinstance(row.get("review_lane"), str) or not row["review_lane"]:
            blockers.append(f"review_lane_missing:{tx_type}")
        for key in (
            "accepted_review_digest",
            "archived_compiled_material_digest",
            "current_material_digest",
        ):
            digest = row.get(key)
            if not isinstance(digest, str) or len(digest) != 64 or any(
                c not in "0123456789abcdef" for c in digest
            ):
                blockers.append(f"invalid_review_material_digest:{tx_type}:{key}")
        if row.get("archive_matches_accepted_digest") is not True or (
            row.get("accepted_review_digest")
            != row.get("archived_compiled_material_digest")
        ):
            blockers.append(f"prior_approval_material_unverified:{tx_type}")
        if row.get("current_material_digest") == row.get("accepted_review_digest"):
            blockers.append(f"already_approved_digest_in_pending:{tx_type}")
        if row.get("current_material_has_unexplained_delta") is not False:
            blockers.append(f"unexplained_review_material_delta:{tx_type}")
        changes = row.get("changed_fields")
        names_recorded = row.get("changed_field_names")
        if (
            not isinstance(changes, list)
            or not changes
            or any(
                not isinstance(change, dict)
                or not isinstance(change.get("field"), str)
                or not change["field"]
                for change in changes
            )
            or not isinstance(names_recorded, list)
            or [change["field"] for change in changes] != names_recorded
        ):
            blockers.append(f"changed_material_fields_incomplete:{tx_type}")
        if row.get("classification_not_semantic_approval") is not True:
            blockers.append(f"review_classification_not_advisory:{tx_type}")
        if row.get("signed_off_for_current_digest") is not False:
            blockers.append(f"current_semantic_signoff_must_remain_false:{tx_type}")
        if row.get("historical_replay_proven") is not False:
            blockers.append(f"historical_replay_unproven:{tx_type}")

    if packet.get("must_not_update_semantic_reviews_automatically") is not True:
        blockers.append("automatic_semantic_approval_not_forbidden")
    if packet.get("independent_human_approval_recorded_by_this_packet") is not False:
        blockers.append("review_packet_must_not_claim_human_approval")
    if packet.get("production_or_testnet_authority") is not False:
        blockers.append("review_packet_must_not_claim_release_authority")
    if packet.get("historical_compatibility_proven") is not False:
        blockers.append("review_packet_must_not_claim_historical_compatibility")
    return blockers


def build_packet() -> dict[str, Any]:
    current_rows, stable_ids, sources = audit._current_rows()
    prior_rows, prior_shape = audit._prior_rows()
    review_source = json.loads(
        (ROOT / "specs/v2/source/semantic_reviews.json").read_text(encoding="utf-8")
    )
    reviews = {
        str(row["tx_type"]): row for row in review_source["transactions"] if isinstance(row, dict)
    }
    previous = {str(row["tx_type"]): row for row in prior_rows}
    if len(current_rows) != 236 or len(reviews) != 236 or len(previous) != 236:
        raise ValueError("v2_review_packet_requires_exactly_236_unique_rows")
    if (
        len({str(row["tx_type"]) for row in current_rows}) != 236
        or len({str(row["tx_type"]) for row in review_source["transactions"]}) != 236
    ):
        raise ValueError("v2_review_packet_has_duplicate_tx_type")

    if (
        any(not isinstance(row.get("stable_id"), str) or not row["stable_id"] for row in current_rows)
        or len({row["stable_id"] for row in current_rows}) != 236
        or len({row.get("stable_id") for row in review_source["transactions"]}) != 236
        or len({row.get("stable_id") for row in prior_rows}) != 236
    ):
        raise ValueError("v2_review_packet_has_duplicate_or_missing_stable_id")

    missing_stable_ids = audit._missing_state_ids(current_rows, stable_ids, sources)
    pending = []
    for row in sorted(current_rows, key=lambda item: str(item["tx_type"])):
        tx_type = str(row["tx_type"])
        if tx_type not in reviews or tx_type not in previous:
            raise ValueError(f"v2_review_packet_missing_review_or_baseline:{tx_type}")
        review = reviews[tx_type]
        # Match the canonical compiler's stable-ID authority, not display type alone.
        if str(review.get("stable_id") or "") != str(row.get("stable_id") or ""):
            raise ValueError(f"v2_review_packet_review_identity_mismatch:{tx_type}")
        if str(previous[tx_type].get("stable_id") or "") != str(row.get("stable_id") or ""):
            raise ValueError(f"v2_review_packet_archive_identity_mismatch:{tx_type}")
        accepted_digest = str(review.get("review_digest") or "")
        current_material = validation.tx_review_material(row)
        current_digest = validation.compact_digest(current_material)
        if current_digest == accepted_digest:
            continue
        old_material = validation.tx_review_material(previous[tx_type])
        old_digest = validation.compact_digest(old_material)
        diffs = field_differences(old_material, current_material)
        failure_deltas = failure_code_deltas(
            old_material.get("failure_codes"), current_material.get("failure_codes")
        )
        if tx_type == "DISPUTE_OPEN":
            review_lane = "handler_source_attribution_and_derived_contract"
        elif tx_type in {"CASE_TYPE_REGISTER", "CASE_BIND_TO_DISPUTE"}:
            review_lane = "case_receipt_compiler_attribution"
        elif tx_type == "CONTENT_FLAG":
            review_lane = "content_flag_duplicate_identity_guard"
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
                "failure_code_deltas": failure_deltas,
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
        "schema": "weall.pr77.v2_semantic_review_decision_packet.v2",
        "kind": "read_only_implementation_comparison",
        "previous_generated_shape": prior_shape,
        "registered_transaction_count": len(current_rows),
        "pending_count": len(pending),
        "newly_stale_not_in_known_inventory": unexpected,
        "known_stale_now_resolved": sorted(KNOWN_STALE - {item["tx_type"] for item in pending}),
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
    integrity_blockers = packet_integrity_blockers(packet)
    packet["packet_integrity_blockers"] = integrity_blockers
    with path.open("x", encoding="utf-8") as output:
        json.dump(packet, output, sort_keys=True, indent=2)
        output.write("\n")
    print(
        json.dumps(
            {
                "pending_count": packet["pending_count"],
                "newly_stale_not_in_known_inventory": packet["newly_stale_not_in_known_inventory"],
                "known_stale_now_resolved": packet["known_stale_now_resolved"],
                "missing_state_stable_ids": packet["missing_state_stable_ids"],
                "review_material_archive_does_not_match_prior_approval": [
                    item["tx_type"]
                    for item in packet["transactions"]
                    if not item["archive_matches_accepted_digest"]
                ],
                "changed_fields_by_tx": {
                    item["tx_type"]: item["changed_field_names"] for item in packet["transactions"]
                },
                "packet_integrity_blockers": integrity_blockers,
                "failure_code_deltas_by_tx": {
                    item["tx_type"]: item["failure_code_deltas"] for item in packet["transactions"]
                },
                "approvals_modified": False,
            },
            sort_keys=True,
            indent=2,
        )
    )
    if integrity_blockers:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
