"""Read-only A03 evidence: unreviewed routes remain blocking, not silently accepted."""

from __future__ import annotations

import copy
import json

from scripts import pr93_v2_semantic_review_inventory as inventory


def _route() -> dict:
    return {
        "stable_id": "ROUTE-TEST",
        "route_key": "GET /v1/example",
        "method": "GET",
        "path": "/v1/example",
        "implementation_source": {
            "path": "src/weall/api/routes_public_parts/content.py",
            "function": "example",
            "line": 120,
        },
        "duplicate_route_key": False,
    }


def _review(route: dict) -> dict:
    return {
        "stable_id": route["stable_id"],
        "route_key": route["route_key"],
        "disposition": "accepted_current_semantic_contract",
        "review_digest": inventory.validation.compact_digest(
            inventory.validation.route_review_material(route)
        ),
    }


def test_new_route_remains_pending_without_review_or_baseline() -> None:
    route = _route()
    original = copy.deepcopy(route)
    result = inventory.classify_route_reviews([route], [], [])
    assert result["pending_route_review_count"] == 1
    assert result["pending_routes"][0]["reasons"] == ["missing_semantic_review"]
    assert result["new_since_generated_route_keys"] == [route["route_key"]]
    assert result["pending_routes"][0]["approved_by_diagnostic"] is False
    assert result["unreviewed_routes_authorized"] is False
    assert route == original


def test_exact_review_is_distinguished_from_stale_and_unapproved_records() -> None:
    route = _route()
    accepted = _review(route)
    clean = inventory.classify_route_reviews([route], [route], [accepted])
    assert clean["pending_route_review_count"] == 0
    assert clean["unreviewed_routes_authorized"] is False

    stale = {**accepted, "review_digest": "0" * 64}
    result = inventory.classify_route_reviews([route], [route], [stale])
    assert result["pending_routes"][0]["reasons"] == ["stale_semantic_review_digest"]

    mismatched = {**accepted, "route_key": "GET /v1/different"}
    result = inventory.classify_route_reviews([route], [route], [mismatched])
    assert "review_route_identity_mismatch" in result["pending_routes"][0]["reasons"]

    unapproved = {**accepted, "disposition": "review_required"}
    result = inventory.classify_route_reviews([route], [route], [unapproved])
    assert "review_not_accepted" in result["pending_routes"][0]["reasons"]


def test_inventory_does_not_hide_orphaned_or_duplicate_identity() -> None:
    route = _route()
    accepted = _review(route)
    orphan = {**accepted, "stable_id": "ROUTE-OLD"}
    result = inventory.classify_route_reviews([route, route], [route], [accepted, orphan, orphan])
    assert result["duplicate_current_route_stable_ids"] == ["ROUTE-TEST"]
    assert result["duplicate_review_route_stable_ids"] == ["ROUTE-OLD"]
    assert result["orphaned_route_review_stable_ids"] == ["ROUTE-OLD"]


def test_live_pr93_public_lobby_route_remains_unreviewed_without_source_mutation() -> None:
    source = inventory.ROOT / "specs/v2/source/semantic_reviews.json"
    before = source.read_bytes()
    report = inventory.build_inventory()
    assert source.read_bytes() == before
    assert report["status"] == "DIAGNOSTIC_ONLY_NOT_SEMANTIC_REVIEW"
    assert report["accepted_reviews_modified"] is False
    assert report["historical_replay_proven"] is False
    assert report["constitutional_or_release_authority_granted"] is False
    assert report["pending_transaction_review_count"] == len(report["pending_transaction_types"])
    route_rows = report["route_review_inventory"]["pending_routes"]
    lobby = [row for row in route_rows if row["route_key"] == "GET /v1/public-lobby/comments"]
    assert len(lobby) == 1
    assert lobby[0]["stable_id"] == "ROUTE-63E26182B51EAFCB"
    assert "missing_semantic_review" in lobby[0]["reasons"]
    assert lobby[0]["present_in_generated_baseline"] is False
    assert lobby[0]["approved_by_diagnostic"] is False
    assert report["route_review_inventory"]["unreviewed_routes_authorized"] is False

    accepted = json.loads(before)["routes"]
    assert not any(row["stable_id"] == lobby[0]["stable_id"] for row in accepted)
