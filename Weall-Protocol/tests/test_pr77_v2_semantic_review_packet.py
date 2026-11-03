from __future__ import annotations

import copy

import pytest

from scripts.pr77_v2_semantic_review_packet import (
    KNOWN_STALE,
    build_packet,
    failure_code_deltas,
    field_differences,
    packet_integrity_blockers,
)


def test_review_diff_distinguishes_absent_from_null() -> None:
    diff = field_differences({"a": None, "b": "old"}, {"b": "new", "c": None})
    assert [entry["field"] for entry in diff] == ["a", "b", "c"]
    assert diff[0]["previous_present"] is True
    assert diff[0]["current_present"] is False
    assert diff[2]["previous_present"] is False
    assert diff[2]["current_present"] is True


def test_v2_stale_review_packet_does_not_approve_18_affected_transactions() -> None:
    packet = build_packet()
    assert packet["registered_transaction_count"] == 236
    assert packet["pending_count"] == 18
    assert {row["tx_type"] for row in packet["transactions"]} == KNOWN_STALE
    assert packet["newly_stale_not_in_known_inventory"] == []
    assert packet["known_stale_now_resolved"] == []
    assert packet["missing_state_stable_ids"] == []
    assert packet["independent_human_approval_recorded_by_this_packet"] is False
    assert packet["historical_compatibility_proven"] is False
    assert packet["must_not_update_semantic_reviews_automatically"] is True
    assert packet_integrity_blockers(packet) == []
    for row in packet["transactions"]:
        assert row["accepted_review_digest"] != row["current_material_digest"]
        assert row["review_lane"]
        assert row["stable_id"]
        assert row["signed_off_for_current_digest"] is False
        assert row["classification_not_semantic_approval"] is True


def test_content_flag_source_change_is_pending_and_never_auto_accepted() -> None:
    packet = build_packet()
    assert packet["schema"] == "weall.pr77.v2_semantic_review_decision_packet.v2"
    rows = {row["tx_type"]: row for row in packet["transactions"]}
    content_flag = rows["CONTENT_FLAG"]
    assert content_flag["changed_field_names"] == ["failure_codes"]
    assert content_flag["archive_matches_accepted_digest"] is True
    assert content_flag["accepted_review_digest"] != content_flag["current_material_digest"]
    assert content_flag["signed_off_for_current_digest"] is False
    assert content_flag["historical_replay_proven"] is False
    assert packet["must_not_update_semantic_reviews_automatically"] is True


def test_failure_code_comparison_preserves_exact_added_and_removed_reasons() -> None:
    before = [
        {"code": "forbidden", "reason": "old"},
        {"code": "invalid_payload", "reason": "unchanged"},
    ]
    after = [
        {"code": "forbidden", "reason": "new"},
        {"code": "invalid_payload", "reason": "unchanged"},
    ]
    delta = failure_code_deltas(before, after)
    assert delta["added"] == [{"code": "forbidden", "reason": "new"}]
    assert delta["removed"] == [{"code": "forbidden", "reason": "old"}]


@pytest.mark.parametrize("invalid", [None, "forbidden", [{"code": "x"}], [1]])
def test_failure_code_comparison_fails_closed_on_malformed_material(invalid: object) -> None:
    with pytest.raises(ValueError, match="v2_review_packet_failure_code"):
        failure_code_deltas([], invalid)


def test_all_eighteen_reviewed_archives_match_accepted_approval() -> None:
    packet = build_packet()
    assert packet["pending_count"] == 18
    assert all(row["archive_matches_accepted_digest"] is True for row in packet["transactions"])
    assert all(
        row["archived_compiled_material_digest"] == row["accepted_review_digest"]
        for row in packet["transactions"]
    )
    assert packet_integrity_blockers(packet) == []


def test_unverified_archived_source_must_block_review_packet_exit() -> None:
    packet = copy.deepcopy(build_packet())
    packet["transactions"][0]["archive_matches_accepted_digest"] = False
    assert "prior_approval_material_unverified:" + packet["transactions"][0][
        "tx_type"
    ] in packet_integrity_blockers(packet)


def test_pretend_reviewer_signoff_and_replay_claims_are_rejected() -> None:
    packet = copy.deepcopy(build_packet())
    packet["transactions"][0]["signed_off_for_current_digest"] = True
    packet["transactions"][0]["historical_replay_proven"] = True
    errors = packet_integrity_blockers(packet)
    tx_type = packet["transactions"][0]["tx_type"]
    assert f"current_semantic_signoff_must_remain_false:{tx_type}" in errors
    assert f"historical_replay_unproven:{tx_type}" in errors


def test_review_packet_shows_exact_rejection_code_delta_per_lane() -> None:
    packet = build_packet()
    rows = {row["tx_type"]: row for row in packet["transactions"]}

    ban_delta = rows["ACCOUNT_BAN"]["failure_code_deltas"]
    assert {
        "code": "forbidden",
        "reason": "severe_sanction_authorization_unimplemented",
    } in ban_delta["added"]
    assert {
        "code": "conflicting_receipt",
        "reason": "duplicate_ban_receipt_conflict",
    } in ban_delta["added"]

    # The old DISPUTE_OPEN scanner traversed the entire dispatcher. Its
    # removed codes must not be mistaken for proof that a real guard vanished.
    open_delta = rows["DISPUTE_OPEN"]["failure_code_deltas"]
    assert {
        "code": "invalid_payload",
        "reason": "missing_target",
    } in open_delta["added"]
    assert {"code": "forbidden", "reason": "system_only"} in open_delta["removed"]

    # The role helper now produces dynamic error code/reason pairs: this
    # analyzer visibility loss does not assert that runtime rejects changed.
    role_delta = rows["ROLE_JUROR_ACTIVATE"]["failure_code_deltas"]
    assert {
        "code": "RolesApplyError",
        "reason": "runtime_apply_failure",
    } in role_delta["added"]
    assert {
        "code": "forbidden",
        "reason": "account_restricted",
    } in role_delta["removed"]


def test_review_packet_integrity_blocks_unexpected_inventory_changes() -> None:
    packet = copy.deepcopy(build_packet())
    packet["newly_stale_not_in_known_inventory"] = ["UNKNOWN_NEW_TX"]
    packet["missing_state_stable_ids"] = ["missing:state:field"]
    errors = packet_integrity_blockers(packet)
    assert "unexpected_stale_transaction" in errors
    assert "missing_state_stable_ids" in errors


def test_dispute_vote_submit_new_severe_appeal_guard_is_review_input_only() -> None:
    """An executable guard still needs real semantic review and replay proof."""
    packet = build_packet()
    rows = [row for row in packet["transactions"] if row["tx_type"] == "DISPUTE_VOTE_SUBMIT"]
    assert len(rows) == 1
    row = rows[0]

    # The severe-appeal guard and reporter-recusal guard both change this
    # transaction's source-bound contract. Neither delta is a review approval.
    assert row["changed_field_names"] == ["failure_codes", "state_reads"]
    assert row["archive_matches_accepted_digest"] is True
    assert row["archived_implementation_source"] == row["current_implementation_source"]
    assert row["failure_code_deltas"] == {
        "added": [
            {"code": "forbidden", "reason": "juror_conflict_reporter"},
            {
                "code": "forbidden",
                "reason": "severe_appeal_fresh_panel_unverified",
            },
        ],
        "removed": [],
    }
    assert row["signed_off_for_current_digest"] is False
    assert row["historical_replay_proven"] is False
    assert packet["must_not_update_semantic_reviews_automatically"] is True


@pytest.mark.parametrize("tx_type", ["DISPUTE_JUROR_ASSIGN", "DISPUTE_JUROR_ACCEPT"])
def test_reporter_recusal_drift_is_bound_to_juror_assignment_and_acceptance(
    tx_type: str,
) -> None:
    packet = build_packet()
    row = next(row for row in packet["transactions"] if row["tx_type"] == tx_type)
    assert row["archive_matches_accepted_digest"] is True
    assert row["archived_implementation_source"] == row["current_implementation_source"]
    assert row["changed_field_names"] == ["failure_codes", "state_reads"]
    assert row["failure_code_deltas"] == {
        "added": [{"code": "forbidden", "reason": "juror_conflict_reporter"}],
        "removed": [],
    }
    state_reads = next(
        change for change in row["changed_fields"] if change["field"] == "state_reads"
    )
    assert {"key:flagged_by", "key:reported_by", "key:reporter"}.issubset(
        set(state_reads["current"])
    )
    assert row["signed_off_for_current_digest"] is False
    assert row["historical_replay_proven"] is False


def test_severe_final_receipt_new_guard_is_bound_to_exact_v2_drift() -> None:
    packet = build_packet()
    row = next(row for row in packet["transactions"] if row["tx_type"] == "DISPUTE_FINAL_RECEIPT")
    assert row["archive_matches_accepted_digest"] is True
    assert row["archived_implementation_source"] == row["current_implementation_source"]
    assert row["changed_field_names"] == ["failure_codes", "state_reads"]
    assert row["failure_code_deltas"] == {
        "added": [
            {"code": "forbidden", "reason": "appeal_pending_panel"},
            {
                "code": "forbidden",
                "reason": "severe_sanction_automatic_appeal_unimplemented",
            },
        ],
        "removed": [],
    }
    assert row["signed_off_for_current_digest"] is False
    assert row["historical_replay_proven"] is False
