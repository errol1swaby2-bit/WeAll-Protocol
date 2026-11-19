#!/usr/bin/env python3
"""Read-only A03 V2 route and transaction semantic-review inventory.

An identity being registered does not mean its behavior has been reviewed.
This diagnostic never rewrites accepted digests, spec artifacts or state.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import audit_v2_semantic_review_drift as audit  # noqa: E402
import compile_v2_spec as compiler  # noqa: E402
import v2_spec_validation as validation  # noqa: E402

Json = dict[str, Any]


def _json(path: Path) -> Json:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid_json_object:{path.name}")
    return value


def _route_rows(stable_ids: Any, sources: Json) -> list[Json]:
    tx_types = {
        str(row["name"]).upper()
        for row in sources["transaction_canon"]["txs"]
        if isinstance(row, dict)
    }
    frontend = compiler._scan_files(compiler.WORKSPACE_ROOT / "web" / "src", {".ts", ".tsx"})
    tests = compiler._scan_files(compiler.ROOT / "tests", {".py"})
    return compiler._scan_route_contracts(
        tx_types, frontend, tests, sources["contract_overrides"], stable_ids
    )


def _duplicate_ids(rows: list[Json]) -> list[str]:
    counts = Counter(str(row.get("stable_id") or "") for row in rows)
    return sorted(key for key, count in counts.items() if count != 1 or not key)


def classify_route_reviews(
    current: list[Json], historical: list[Json], reviews: list[Json]
) -> Json:
    """Compare actual AST routes to prior output and explicitly accepted reviews.

    This function never considers a mere candidate digest an approval.
    Missing and malformed reviews remain visible rather than synthesized.
    """
    current_ids = {str(row.get("stable_id") or "") for row in current}
    historical_by_id = {str(row.get("stable_id") or ""): row for row in historical}
    reviews_by_id = {str(row.get("stable_id") or ""): row for row in reviews}
    pending: list[Json] = []
    new_since_generated: list[str] = []

    for row in sorted(current, key=lambda item: str(item.get("route_key") or "")):
        sid = str(row.get("stable_id") or "")
        route_key = str(row.get("route_key") or "")
        review = reviews_by_id.get(sid)
        historical_row = historical_by_id.get(sid)
        material = validation.route_review_material(row)
        current_digest = validation.compact_digest(material)
        if historical_row is None:
            new_since_generated.append(route_key)

        reasons: list[str] = []
        if review is None:
            reasons.append("missing_semantic_review")
        else:
            if review.get("route_key") != route_key:
                reasons.append("review_route_identity_mismatch")
            if review.get("disposition") != "accepted_current_semantic_contract":
                reasons.append("review_not_accepted")
            if review.get("review_digest") != current_digest:
                reasons.append("stale_semantic_review_digest")
        if historical_row is not None and historical_row.get("route_key") != route_key:
            reasons.append("generated_baseline_route_identity_mismatch")
        if reasons:
            pending.append(
                {
                    "route_key": route_key,
                    "stable_id": sid,
                    "implementation_source": material.get("implementation_source"),
                    "reasons": reasons,
                    "candidate_digest_not_approved": current_digest,
                    "recorded_review_digest": (
                        str(review.get("review_digest") or "") if review is not None else None
                    ),
                    "present_in_generated_baseline": historical_row is not None,
                    "approved_by_diagnostic": False,
                }
            )

    return {
        "current_route_count": len(current),
        "historical_generated_route_count": len(historical),
        "recorded_route_review_count": len(reviews),
        "pending_route_review_count": len(pending),
        "pending_routes": pending,
        "new_since_generated_route_keys": sorted(new_since_generated),
        "orphaned_route_review_stable_ids": sorted(set(reviews_by_id) - current_ids),
        "duplicate_current_route_stable_ids": _duplicate_ids(current),
        "duplicate_review_route_stable_ids": _duplicate_ids(reviews),
        "unreviewed_routes_authorized": False,
    }


def build_inventory() -> Json:
    tx_rows, stable_ids, sources = audit._current_rows()
    reviews = _json(ROOT / "specs/v2/source/semantic_reviews.json")
    historical_routes = _json(ROOT / "generated/v2/route_contract_map.json")
    current_routes = _route_rows(stable_ids, sources)
    route_report = classify_route_reviews(
        current_routes,
        historical_routes.get("routes") or [],
        reviews.get("routes") or [],
    )

    tx_reviews = {
        str(row.get("stable_id") or ""): row
        for row in reviews.get("transactions") or []
        if isinstance(row, dict)
    }
    tx_pending = []
    for row in tx_rows:
        review = tx_reviews.get(str(row.get("stable_id") or ""))
        digest = validation.compact_digest(validation.tx_review_material(row))
        if (
            review is None
            or review.get("disposition") != "accepted_current_semantic_contract"
            or digest != review.get("review_digest")
        ):
            tx_pending.append(str(row.get("tx_type") or ""))

    return {
        "status": "DIAGNOSTIC_ONLY_NOT_SEMANTIC_REVIEW",
        "schema": "weall.pr93.v2_semantic_inventory.read_only.v1",
        "transaction_count": len(tx_rows),
        "pending_transaction_review_count": len(tx_pending),
        "pending_transaction_types": sorted(tx_pending),
        "route_review_inventory": route_report,
        "missing_state_stable_ids": audit._missing_state_ids(tx_rows, stable_ids, sources),
        "accepted_reviews_modified": False,
        "historical_replay_proven": False,
        "constitutional_or_release_authority_granted": False,
    }


def main() -> int:
    print(json.dumps(build_inventory(), sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
