"""Fail-closed tests for synthetic old/new role and receipt-boundary classification.

The six known dedupe deltas are an explicit evidence classification only.
Passing cannot update semantic approvals or prove real retained historical blocks.
"""

from __future__ import annotations

import copy

import pytest

from scripts.pr77_legacy_role_parity_adjudication import (
    ParityAdjudicationError,
    adjudicate,
)
from scripts.pr77_legacy_role_parity_probe import CONDITIONS, TX_AND_ROLE


def _reports() -> tuple[dict, dict]:
    rows = []
    for tx_type, _role in TX_AND_ROLE:
        for version in ("absent", 1):
            for condition in CONDITIONS:
                rows.append(
                    {
                        "tx_type": tx_type,
                        "version": version,
                        "condition": condition,
                        "status": "accepted",
                        "metadata": {
                            "applied": tx_type,
                            "deduped": False,
                        },
                        "input_state_root": "a" * 64,
                        "state_root": "b" * 64,
                    }
                )
    base = {
        "schema": "weall.pr77.synthetic_legacy_role_parity.v1",
        "case_count": len(rows),
        "cases": rows,
    }
    current = copy.deepcopy(base)
    for item in current["cases"]:
        if (
            item["tx_type"]
            in {
                "ROLE_JUROR_ACTIVATE",
                "ROLE_JUROR_REINSTATE",
                "ROLE_NODE_OPERATOR_ACTIVATE",
            }
            and item["condition"] == "baseline"
        ):
            item["metadata"]["deduped"] = True
    return base, current


def test_only_six_named_legacy_metadata_deltas_have_equal_canonical_receipts() -> None:
    base, candidate = _reports()
    result = adjudicate(base, candidate)
    assert result["ok"] is True
    assert result["case_count"] == 126
    assert result["strict_full_applier_metadata_parity"] is False
    assert result["known_noncommitted_metadata_difference_count"] == 6
    assert result["unclassified_differences"] == 0
    assert result["per_case_synthetic_receipts_root_parity"] is True
    assert result["per_case_consensus_state_root_parity"] is True
    assert len(result["synthetic_receipts_batch_root"]) == 64
    assert result["real_committed_role_blocks_proven"] is False
    assert result["authentic_retained_history_proven"] is False
    assert result["v2_semantic_review_approved"] is False
    assert result["release_ready"] is False


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("lost_case", "truncated_or_extra_cases"),
        ("wrong_identity", "case_identity_mismatch"),
        ("changed_input_root", "input_state_root_changed"),
        ("changed_state_root", "consensus_state_root_changed"),
        ("changed_status", "canonical_receipt_field_changed"),
        ("changed_rejection", "canonical_receipt_field_changed"),
        ("changed_success_payload", "unclassified_legacy_difference"),
        ("changed_other_metadata", "unexpected_metadata_delta"),
        ("changed_dedupe_direction", "documented_metadata_difference_inventory_changed"),
        ("changed_known_scenario", "unclassified_legacy_difference"),
    ],
)
def test_unclassified_changes_never_pass(mutation: str, error: str) -> None:
    base, candidate = _reports()
    row = candidate["cases"][0]
    if mutation == "lost_case":
        candidate["cases"].pop()
    elif mutation == "wrong_identity":
        row["tx_type"] = "WRONG_TX"
    elif mutation == "changed_input_root":
        row["input_state_root"] = "c" * 64
    elif mutation == "changed_state_root":
        row["state_root"] = "c" * 64
    elif mutation == "changed_status":
        row["status"] = "rejected"
        row["code"] = "forbidden"
        row["reason"] = "different"
    elif mutation == "changed_rejection":
        base_row = base["cases"][0]
        base_row["status"] = "rejected"
        base_row["code"] = "forbidden"
        base_row["reason"] = "original"
        row["status"] = "rejected"
        row["code"] = "forbidden"
        row["reason"] = "different"
    elif mutation == "changed_success_payload":
        row["additional_visible_field"] = True
    elif mutation == "changed_other_metadata":
        for item in candidate["cases"]:
            if item["tx_type"] == "ROLE_JUROR_ACTIVATE" and item["condition"] == "baseline":
                item["metadata"]["applied"] = "WRONG"
                break
    elif mutation == "changed_dedupe_direction":
        for item in candidate["cases"]:
            if item["tx_type"] == "ROLE_JUROR_ACTIVATE" and item["condition"] == "baseline":
                item["metadata"]["deduped"] = False
    elif mutation == "changed_known_scenario":
        row["metadata"]["deduped"] = True
    else:
        raise AssertionError("unhandled_mutation")
    with pytest.raises(ParityAdjudicationError, match=error):
        adjudicate(base, candidate)


def test_report_schema_mismatch_fails_closed() -> None:
    old, new = _reports()
    new["schema"] = "unknown"
    with pytest.raises(ParityAdjudicationError, match="different_report_schemas"):
        adjudicate(old, new)
