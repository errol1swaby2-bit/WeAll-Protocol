#!/usr/bin/env python3
"""Adjudicate synthetic legacy role parity at the canonical receipt boundary.

Only six *known* non-committed deduped metadata differences are admissible
for this diagnostic. No V2 semantic review is approved; no retained historical
role blocks, signed consensus receipts, or independent BFT network are proven.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scripts.pr77_legacy_role_parity_probe import CONDITIONS, TX_AND_ROLE
from weall.runtime.block_hash import compute_receipts_root

Json = dict[str, Any]

_ALLOWED_DEDUPE_TYPES = frozenset(
    {"ROLE_JUROR_ACTIVATE", "ROLE_JUROR_REINSTATE", "ROLE_NODE_OPERATOR_ACTIVATE"}
)
_ALLOWED_VERSION_VALUES = ("absent", 1)


class ParityAdjudicationError(ValueError):
    """An unexpected execution, state, metadata, or commitment change."""


def _ordered_case_keys() -> list[tuple[str, object, str]]:
    return [
        (tx_type, version, condition)
        for tx_type, _role in TX_AND_ROLE
        for version in _ALLOWED_VERSION_VALUES
        for condition in CONDITIONS
    ]


def _receipt_for_case(row: Json, position: int) -> Json:
    """Construct the canonical receipt FIELDS used by builder and replay.

    This is not a committed historical receipt: the deterministic synthetic
    tx_id only identifies a test scenario, without cryptographic signatures
    or canonical block admission. The CI pins both checkout implementations'
    block_builder.py and block_replay.py to identical source bytes.
    """
    accepted = row["status"] == "accepted"
    tx_type = row["tx_type"]
    system = tx_type in {
        "ROLE_VALIDATOR_ACTIVATE",
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "ROLE_EMISSARY_SEAT",
        "ROLE_GOV_EXECUTOR_SET",
    }
    receipt: Json = {
        "tx_id": f"pr77:synthetic:legacy-role:{position}",
        "tx_type": tx_type,
        "signer": "SYSTEM" if system else "@alice",
        "nonce": 24,
        "ok": accepted,
    }
    if not accepted:
        receipt["code"] = row["code"] or "apply_error"
        receipt["reason"] = row["reason"] or "rejected"
        if row.get("details") is not None:
            receipt["details"] = row["details"]
    return receipt


def adjudicate(base: Json, candidate: Json) -> Json:
    keys = _ordered_case_keys()
    base_rows = base.get("cases")
    candidate_rows = candidate.get("cases")
    if not isinstance(base_rows, list) or not isinstance(candidate_rows, list):
        raise ParityAdjudicationError("missing_case_inventory")
    if base.get("case_count") != len(keys) or candidate.get("case_count") != len(keys):
        raise ParityAdjudicationError("wrong_case_count")
    if len(base_rows) != len(keys) or len(candidate_rows) != len(keys):
        raise ParityAdjudicationError("truncated_or_extra_cases")
    if base.get("schema") != candidate.get("schema"):
        raise ParityAdjudicationError("different_report_schemas")
    if base.get("schema") != "weall.pr77.synthetic_legacy_role_parity.v1":
        raise ParityAdjudicationError("unexpected_report_schema")

    known_deltas: list[Json] = []
    original_receipts: list[Json] = []
    candidate_receipts: list[Json] = []
    for position, (key, old, new) in enumerate(
        zip(keys, base_rows, candidate_rows, strict=True), start=1
    ):
        if not isinstance(old, dict) or not isinstance(new, dict):
            raise ParityAdjudicationError(f"invalid_case_record:{position}")
        for row in (old, new):
            if (row.get("tx_type"), row.get("version"), row.get("condition")) != key:
                raise ParityAdjudicationError(f"case_identity_mismatch:{position}")
            if row.get("status") not in {"accepted", "rejected"}:
                raise ParityAdjudicationError(f"unknown_case_status:{position}")
            if not isinstance(row.get("state_root"), str) or not isinstance(
                row.get("input_state_root"), str
            ):
                raise ParityAdjudicationError(f"missing_consensus_state_root:{position}")

        if old["input_state_root"] != new["input_state_root"]:
            raise ParityAdjudicationError(f"input_state_root_changed:{position}")
        if old["state_root"] != new["state_root"]:
            raise ParityAdjudicationError(f"consensus_state_root_changed:{position}")

        old_receipt = _receipt_for_case(old, position)
        new_receipt = _receipt_for_case(new, position)
        if old_receipt != new_receipt:
            raise ParityAdjudicationError(f"canonical_receipt_field_changed:{position}")
        if compute_receipts_root(receipts=[old_receipt]) != compute_receipts_root(
            receipts=[new_receipt]
        ):
            raise ParityAdjudicationError(f"canonical_receipt_root_changed:{position}")
        original_receipts.append(old_receipt)
        candidate_receipts.append(new_receipt)

        if old == new:
            continue
        if (
            old.get("status") != "accepted"
            or new.get("status") != "accepted"
            or key[0] not in _ALLOWED_DEDUPE_TYPES
            or key[1] not in _ALLOWED_VERSION_VALUES
            or key[2] != "baseline"
            or {k: v for k, v in old.items() if k != "metadata"}
            != {k: v for k, v in new.items() if k != "metadata"}
        ):
            raise ParityAdjudicationError(f"unclassified_legacy_difference:{position}")
        old_meta = old.get("metadata")
        new_meta = new.get("metadata")
        if not isinstance(old_meta, dict) or not isinstance(new_meta, dict):
            raise ParityAdjudicationError(f"missing_success_metadata:{position}")
        if (
            old_meta.get("deduped") is not False
            or new_meta.get("deduped") is not True
            or {k: v for k, v in old_meta.items() if k != "deduped"}
            != {k: v for k, v in new_meta.items() if k != "deduped"}
        ):
            raise ParityAdjudicationError(f"unexpected_metadata_delta:{position}")
        known_deltas.append(
            {
                "case_index": position,
                "tx_type": key[0],
                "version": key[1],
                "condition": key[2],
                "changed_only": "metadata.deduped",
                "pinned_main": False,
                "candidate": True,
            }
        )

    expected_deltas = {
        (name, version, "baseline")
        for name in _ALLOWED_DEDUPE_TYPES
        for version in _ALLOWED_VERSION_VALUES
    }
    actual_deltas = {(case["tx_type"], case["version"], case["condition"]) for case in known_deltas}
    if actual_deltas != expected_deltas or len(known_deltas) != 6:
        raise ParityAdjudicationError("documented_metadata_difference_inventory_changed")

    original_batch_root = compute_receipts_root(receipts=original_receipts)
    candidate_batch_root = compute_receipts_root(receipts=candidate_receipts)
    if original_batch_root != candidate_batch_root:
        raise ParityAdjudicationError("synthetic_batch_receipts_root_mismatch")

    return {
        "ok": True,
        "schema": "weall.pr77.synthetic_legacy_role_boundary_adjudication.v1",
        "case_count": len(keys),
        "strict_full_applier_metadata_parity": False,
        "known_noncommitted_metadata_differences": known_deltas,
        "known_noncommitted_metadata_difference_count": 6,
        "unclassified_differences": 0,
        "per_case_synthetic_receipts_root_parity": True,
        "per_case_consensus_state_root_parity": True,
        "synthetic_receipts_batch_root": original_batch_root,
        "real_committed_role_blocks_proven": False,
        "authentic_retained_history_proven": False,
        "prior_version_compatibility_proven": False,
        "independent_two_node_consensus_proven": False,
        "v2_semantic_review_approved": False,
        "release_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink() or not args.report.parent.is_dir():
        raise SystemExit("invalid_report_destination")
    for source in (args.old, args.candidate):
        if not source.is_file() or source.is_symlink() or source.resolve() == args.report.resolve():
            raise SystemExit("invalid_report_source")
    try:
        old = json.loads(args.old.read_text(encoding="utf-8"))
        new = json.loads(args.candidate.read_text(encoding="utf-8"))
        result = adjudicate(old, new)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"ok": False, "reason": str(exc)}, sort_keys=True))
        return 1
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "ok": True,
                "cases": result["case_count"],
                "noncommitted_known_deltas": result["known_noncommitted_metadata_difference_count"],
                "synthetic_receipts_root_equal": result["per_case_synthetic_receipts_root_parity"],
                "historical_approval": False,
                "release_ready": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
