from __future__ import annotations

from weall.runtime.helper_merge_admission import admit_helper_merge
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution


def _resolution(lane_id: str) -> HelperLaneResolution:
    return HelperLaneResolution(lane_id=lane_id, helper_id="helper-1", mode="helper", certificate=None)


def test_helper_merge_decision_surfaces_cross_lane_receipt_conflict_batch6() -> None:
    decision = admit_helper_merge(
        resolutions=(_resolution("lane-a"), _resolution("lane-b")),
        lane_results_by_id={
            "lane-a": {"receipts": [{"tx_id": "t1"}], "state_delta": {"a": 1}},
            "lane-b": {"receipts": [{"tx_id": "t1"}], "state_delta": {"b": 2}},
        },
    )
    assert decision.accepted is False
    assert decision.code == "cross_lane_receipt_tx_id_conflict"
    assert decision.failure_stage == "lane_result"
    assert decision.lane_id == "lane-b"
    assert decision.conflicting_tx_ids == ("t1",)
    payload = decision.to_json()
    assert payload["conflicting_tx_ids"] == ["t1"]
    assert payload["detail"] == "receipt tx id overlap across helper lanes"


def test_helper_merge_decision_surfaces_merge_conflict_key_batch6() -> None:
    decision = admit_helper_merge(
        resolutions=(_resolution("lane-a"), _resolution("lane-b")),
        lane_results_by_id={
            "lane-a": {"receipts": [{"tx_id": "t1"}], "state_delta": {"balances:alice": 5}},
            "lane-b": {"receipts": [{"tx_id": "t2"}], "state_delta": {"balances:alice": 7}},
        },
    )
    assert decision.accepted is False
    assert decision.code == "merge_conflict:balances:alice"
    assert decision.failure_stage == "merge"
    assert decision.lane_id == "lane-b"
    assert decision.conflicting_state_keys == ("balances:alice",)
    assert decision.detail == "state delta key written by more than one helper lane"


def test_helper_merge_decision_success_payload_is_stable_batch6() -> None:
    decision = admit_helper_merge(
        resolutions=(_resolution("lane-a"),),
        lane_results_by_id={
            "lane-a": {"receipts": [{"tx_id": "t1"}], "state_delta": {"balances:alice": 5}},
        },
    )
    assert decision.accepted is True
    payload = decision.to_json()
    assert payload["code"] == "accepted"
    assert payload["detail"] == "merge accepted"
    assert payload["failure_stage"] == ""
    assert payload["conflicting_state_keys"] == []
    assert payload["conflicting_tx_ids"] == []
