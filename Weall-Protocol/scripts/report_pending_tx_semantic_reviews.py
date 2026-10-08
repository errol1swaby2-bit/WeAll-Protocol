#!/usr/bin/env python3
"""Read-only review-candidate report for stale v2 transaction semantic bindings.

This deliberately NEVER updates semantic_reviews.json and NEVER attests that a
maintainer or independent reviewer accepted a changed transaction contract.
It uses the same scanners/digest function as compile_v2_spec.py, but bypasses
only the *acceptance check* to produce candidate material for human review.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from compile_v2_spec import (
    ROOT,
    WORKSPACE_ROOT,
    StableIdRegistry,
    _load_sources,
    _scan_files,
    _scan_route_contracts,
    _scan_transaction_contracts,
)
from v2_spec_validation import compact_digest, tx_review_material

TARGET_TX_TYPES = (
    "ACCOUNT_REGISTER",
    "BALANCE_TRANSFER",
    "BLOCK_REWARD_DISTRIBUTE",
    "FEE_PAY",
)


def build_report() -> dict[str, Any]:
    """Derive candidate digests from canonical current source without approval."""
    sources = _load_sources()
    canon = sources["transaction_canon"]
    tx_names = {
        str(row.get("name") or "").strip().upper()
        for row in canon.get("txs") or []
        if isinstance(row, dict)
    }
    stable_ids = StableIdRegistry.from_payload(sources["stable_ids"])
    frontend_files = _scan_files(WORKSPACE_ROOT / "web" / "src", {".ts", ".tsx"})
    test_files = _scan_files(ROOT / "tests", {".py"})
    route_rows = _scan_route_contracts(
        tx_names, frontend_files, test_files, sources["contract_overrides"], stable_ids
    )
    tx_rows = _scan_transaction_contracts(
        canon,
        sources["activation_profiles"],
        sources["protocol_registry"],
        sources["contract_overrides"],
        route_rows,
        frontend_files,
        test_files,
        stable_ids,
        sources["transaction_appliers"],
    )
    current = {row["tx_type"]: row for row in tx_rows}
    accepted = {
        row["tx_type"]: row for row in sources["semantic_reviews"].get("transactions") or []
    }
    entries = []
    for tx_type in TARGET_TX_TYPES:
        if tx_type not in current or tx_type not in accepted:
            raise ValueError(f"missing_semantic_review_target:{tx_type}")
        row = current[tx_type]
        previous = accepted[tx_type]
        if str(row["stable_id"]) != str(previous["stable_id"]):
            raise ValueError(f"semantic_stable_id_changed:{tx_type}")
        material = tx_review_material(row)
        candidate = compact_digest(material)
        old_digest = str(previous["review_digest"])
        entries.append(
            {
                "tx_type": tx_type,
                "stable_id": row["stable_id"],
                "previous_accepted_digest": old_digest,
                "candidate_digest": candidate,
                "candidate_differs_from_accepted": candidate != old_digest,
                "acceptance_status": "PENDING_MAINTAINER_REVIEW"
                if candidate != old_digest
                else "PREVIOUS_DIGEST_MATCHES",
                "independent_review_completed": False,
                "material_for_review": material,
            }
        )
    return {
        "schema": "weall.v2.pending_tx_semantic_review_candidates",
        "authority": "diagnostic_only_not_a_review_attestation",
        "changes_accepted": False,
        "source": "current_checkout_source_scanner",
        "transactions": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output JSON file (default: print to stdout).",
    )
    args = parser.parse_args()
    report = build_report()
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(payload, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"wrote review candidates to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
