#!/usr/bin/env python3
"""Apply only the exact PR #93 development contract decision recorded by the maintainer."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path

from pr77_v2_semantic_review_packet import (
    ARCHIVED_PACKET,
    ARCHIVED_PACKET_DIGEST,
    audit,
    build_live_packet,
    packet_integrity_blockers,
    validation,
)
from pr93_v2_semantic_review_inventory import _route_rows

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT.parent / "docs/integration"
CANDIDATE = DOCS / "PR93_DEVELOPMENT_SEMANTIC_ACCEPTANCE_CANDIDATE.json"
DECISION = DOCS / "PR93_DEVELOPMENT_SEMANTIC_ACCEPTANCE_DECISION.json"
MANIFEST = ROOT / "specs/v2/source/semantic_reviews.json"
CANDIDATE_BLOB = "77c3c17d57069e16fea5ca899e576cf49bfae4a2"
ACCEPTED_HEAD = "730166e048bea33ec90bc1190f3aeb187bccb75b"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SystemExit(reason)


def main() -> None:
    require(not ARCHIVED_PACKET.exists(), "pre_acceptance_archive_already_exists")
    raw = CANDIDATE.read_bytes()
    blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()
    require(blob == CANDIDATE_BLOB, "approved_candidate_blob_mismatch")
    candidate = json.loads(raw)
    decision = json.loads(DECISION.read_text(encoding="utf-8"))
    require(
        decision["decision"] == "ACCEPT_EXACT_CURRENT_DEVELOPMENT_CONTRACTS"
        and decision["candidate_commit"] == ACCEPTED_HEAD
        and decision["candidate_git_blob"] == CANDIDATE_BLOB
        and decision["validated_packet_compact_sha256"] == ARCHIVED_PACKET_DIGEST
        and decision["validated_test_count"] == 631
        and decision["validated_workflow_run"] == 44150569172
        and decision["independent_review"] is False,
        "explicit_maintainer_decision_mismatch",
    )

    historical = build_live_packet()
    require(not packet_integrity_blockers(historical), "pre_acceptance_packet_integrity_failed")
    require(
        validation.compact_digest(historical) == ARCHIVED_PACKET_DIGEST,
        "pre_acceptance_packet_changed_since_approval",
    )
    tx_rows, stable_ids, sources = audit._current_rows()
    routes = _route_rows(stable_ids, sources)
    before = json.loads(MANIFEST.read_text(encoding="utf-8"))
    after = copy.deepcopy(before)
    old_pending = {row["stable_id"]: row for row in historical["transactions"]}
    require(
        len(candidate["transactions"]) == len(old_pending) == 20
        and len(candidate["routes"]) == 1
        and len(tx_rows) == 236
        and len(routes) == 162,
        "approved_inventory_count_mismatch",
    )
    require(
        {row["stable_id"] for row in candidate["transactions"]} == set(old_pending),
        "approved_transaction_set_mismatch",
    )
    reviewed_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for group, current, material_fn, key in (
        ("transactions", tx_rows, validation.tx_review_material, "tx_type"),
        ("routes", routes, validation.route_review_material, "route_key"),
    ):
        current_by_id = {row["stable_id"]: row for row in current}
        reviewed_by_id = {row["stable_id"]: row for row in after[group]}
        require(
            len(current_by_id) == len(current) == len(reviewed_by_id) == len(after[group]),
            f"duplicate_or_missing_{group}_identity",
        )
        for item in candidate[group]:
            sid = item["stable_id"]
            row = current_by_id[sid]
            review = reviewed_by_id[sid]
            material = material_fn(row)
            actual = validation.compact_digest(material)
            require(
                row[key] == review[key] == item[key]
                and actual == item["candidate_digest"]
                and review["review_digest"] == item["previous_review_digest"]
                and material["implementation_source"] == item["implementation_source"],
                f"approved_identity_or_digest_mismatch:{sid}",
            )
            if group == "transactions":
                old = old_pending[sid]
                require(
                    old["current_material_digest"] == actual
                    and old["accepted_review_digest"] == review["review_digest"],
                    f"approved_historical_material_mismatch:{sid}",
                )
            else:
                require(
                    sid == "ROUTE-63E26182B51EAFCB" and review["disposition"] == "review_required",
                    "unexpected_route_decision",
                )
            review.update(
                disposition="accepted_current_semantic_contract",
                review_digest=actual,
                implementation_source=row["implementation_source"],
                reviewer="Repository maintainer; explicit project-conversation acceptance (AI-assisted)",
                reviewed_at=reviewed_at,
                review_method="exact_pr93_development_candidate_maintainer_acceptance_with_regression_evidence",
                independent_review=False,
                authority_effect=decision["authority_effect"],
            )

    # This is the original strict validator, not a discovery-mode substitution.
    result = validation.apply_semantic_reviews(copy.deepcopy(tx_rows), copy.deepcopy(routes), after)
    require(
        result["validation_result"] == "PASS_COMPLETE_MAINTAINER_SEMANTIC_REVIEW_BINDINGS"
        and result["independent_review_complete"] is False
        and result["independent_review_gate"] == "deferred_to_launch_authorization",
        "strict_review_binding_or_launch_boundary_failed",
    )
    for group in ("transactions", "routes"):
        expected = {row["stable_id"] for row in candidate[group]}
        changed = {
            old["stable_id"]
            for old, new in zip(before[group], after[group], strict=True)
            if old != new
        }
        require(changed == expected, f"unexpected_review_mutation:{group}")
    ARCHIVED_PACKET.write_text(
        json.dumps(historical, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    MANIFEST.write_text(
        json.dumps(after, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True))
    print("Applied exact 20 transaction and one route decisions; no launch authority.")


if __name__ == "__main__":
    main()
