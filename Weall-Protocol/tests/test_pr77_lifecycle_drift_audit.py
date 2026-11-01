from __future__ import annotations

from scripts.pr77_lifecycle_drift_audit import (
    KNOWN_ROLE_VECTORS,
    build_diagnostic,
    leaf_diffs,
)


def test_json_pointer_differences_escape_reserved_tokens() -> None:
    old = {"a/b": {"~key": [1, {"x": False}]}, "only_old": "old"}
    new = {"a/b": {"~key": [1, {"x": True}]}, "only_new": "new"}
    diffs = leaf_diffs(old, new)
    assert [entry["path"] for entry in diffs] == [
        "/a~1b/~0key/1/x",
        "/only_new",
        "/only_old",
    ]
    assert diffs[0]["old"] is False
    assert diffs[0]["new"] is True


def test_json_pointer_differences_detect_list_growth() -> None:
    diffs = leaf_diffs(["a", "b"], ["b", "a", "c"])
    assert [entry["path"] for entry in diffs] == ["/0", "/1", "/2"]
    assert diffs[-1]["old"] == "<missing>"
    assert diffs[-1]["new"] == "c"


def test_refreshed_lifecycle_manifest_has_no_unreviewed_drift() -> None:
    report, candidate = build_diagnostic()
    assert candidate["schema"] == "weall.tx_lifecycle_assurance.v1"
    assert len(candidate["rows"]) == 236
    # Expected to be empty after the authorized source-bound four-row refresh.
    # Any new drift is still fail-closed rather than accepted as semantic proof.
    assert report["changed_tx_types"] == []
    assert set(report["changed_tx_types"]) <= KNOWN_ROLE_VECTORS
    assert report["changed_outside_four_known_role_vectors"] == []
    assert report["changed_top_level_fields"] == []
    assert report["all_changed_rows_match_deepcopy_oracle"] is True
    assert report["authoritative_historical_chain_provided"] is False
    assert report["independent_review_or_semantic_approval"] is False
    assert report["must_not_refresh_tracked_manifest_automatically"] is True
    for entry in report["investigations"].values():
        assert entry["deepcopy_metadata_equal"] is True
        assert entry["deepcopy_state_equal"] is True
        assert entry["deepcopy_root_equal"] is True
        assert entry["historical_pre_fix_state_available"] is False
        assert entry["changed_pointers"]
        assert isinstance(entry["current_state_transition_paths"], list)
        if entry["current_fixture_before_root"] == entry["current_fixture_after_root"]:
            assert entry["current_state_transition_paths"] == []
