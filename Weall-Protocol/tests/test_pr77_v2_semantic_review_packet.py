from __future__ import annotations

from scripts.pr77_v2_semantic_review_packet import (
    KNOWN_STALE,
    build_packet,
    field_differences,
)


def test_review_diff_distinguishes_absent_from_null() -> None:
    diff = field_differences({"a": None, "b": "old"}, {"b": "new", "c": None})
    assert [entry["field"] for entry in diff] == ["a", "b", "c"]
    assert diff[0]["previous_present"] is True
    assert diff[0]["current_present"] is False
    assert diff[2]["previous_present"] is False
    assert diff[2]["current_present"] is True


def test_v2_stale_review_packet_does_not_approve_15_affected_transactions() -> None:
    packet = build_packet()
    assert packet["registered_transaction_count"] == 236
    assert packet["pending_count"] == 15
    assert {row["tx_type"] for row in packet["transactions"]} == KNOWN_STALE
    assert packet["newly_stale_not_in_known_15"] == []
    assert packet["known_stale_now_resolved"] == []
    assert packet["missing_state_stable_ids"] == []
    assert packet["independent_human_approval_recorded_by_this_packet"] is False
    assert packet["historical_compatibility_proven"] is False
    assert packet["must_not_update_semantic_reviews_automatically"] is True
    for row in packet["transactions"]:
        assert row["accepted_review_digest"] != row["current_material_digest"]
        assert row["review_lane"]
        assert row["stable_id"]
        assert row["signed_off_for_current_digest"] is False
        assert row["classification_not_semantic_approval"] is True
