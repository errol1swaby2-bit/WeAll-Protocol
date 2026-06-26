from __future__ import annotations

from weall.runtime.helper_merge_admission import (
    admit_helper_merge,
    canonical_receipts_root,
    canonical_state_delta_hash,
)
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution


class _Cert:
    def __init__(self, receipts_root: str = "", lane_delta_hash: str = "") -> None:
        self.receipts_root = receipts_root
        self.lane_delta_hash = lane_delta_hash


def _resolution(
    *,
    lane_id: str,
    helper_id: str = "helper-1",
    mode: str = "helper",
    receipts_root: str = "",
    lane_delta_hash: str = "",
):
    cert = None
    if receipts_root or lane_delta_hash:
        cert = _Cert(receipts_root=receipts_root, lane_delta_hash=lane_delta_hash)
    return HelperLaneResolution(
        lane_id=lane_id,
        helper_id=helper_id,
        mode=mode,
        certificate=cert,
    )


def test_helper_merge_admission_accepts_matching_certificate_hashes_batch8() -> None:
    receipts = [{"tx_id": "t1", "status": "ok"}]
    delta = {"balances:alice": 5}
    decision = admit_helper_merge(
        resolutions=(
            _resolution(
                lane_id="lane-a",
                receipts_root=canonical_receipts_root(receipts),
                lane_delta_hash=canonical_state_delta_hash(delta),
            ),
        ),
        lane_results_by_id={
            "lane-a": {
                "receipts": receipts,
                "state_delta": delta,
            }
        },
    )
    assert decision.accepted is True
    assert decision.code == "accepted"
    assert decision.lane_count == 1


def test_helper_merge_admission_rejects_receipts_root_mismatch_batch8() -> None:
    receipts = [{"tx_id": "t1", "status": "ok"}]
    delta = {"balances:alice": 5}
    decision = admit_helper_merge(
        resolutions=(
            _resolution(
                lane_id="lane-a",
                receipts_root="wrong-root",
                lane_delta_hash=canonical_state_delta_hash(delta),
            ),
        ),
        lane_results_by_id={
            "lane-a": {
                "receipts": receipts,
                "state_delta": delta,
            }
        },
    )
    assert decision.accepted is False
    assert decision.code == "receipts_root_mismatch"


def test_helper_merge_admission_rejects_state_delta_hash_mismatch_batch8() -> None:
    receipts = [{"tx_id": "t1", "status": "ok"}]
    delta = {"balances:alice": 5}
    decision = admit_helper_merge(
        resolutions=(
            _resolution(
                lane_id="lane-a",
                receipts_root=canonical_receipts_root(receipts),
                lane_delta_hash="wrong-delta-hash",
            ),
        ),
        lane_results_by_id={
            "lane-a": {
                "receipts": receipts,
                "state_delta": delta,
            }
        },
    )
    assert decision.accepted is False
    assert decision.code == "state_delta_hash_mismatch"


def test_helper_merge_admission_rejects_merge_conflict_batch8() -> None:
    res_a = _resolution(lane_id="lane-a", mode="helper")
    res_b = _resolution(lane_id="lane-b", mode="fallback")
    decision = admit_helper_merge(
        resolutions=(res_a, res_b),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"balances:alice": 5},
            },
            "lane-b": {
                "receipts": [{"tx_id": "t2"}],
                "state_delta": {"balances:alice": 7},
            },
        },
    )
    assert decision.accepted is False
    assert decision.code == "merge_conflict:balances:alice"


def test_helper_merge_admission_rejects_serial_equivalence_failure_batch8() -> None:
    res = _resolution(lane_id="lane-a")
    decision = admit_helper_merge(
        resolutions=(res,),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"balances:alice": 5},
            },
        },
        serial_equivalence_fn=lambda candidates: False,
    )
    assert decision.accepted is False
    assert decision.code == "serial_equivalence_failed"


def test_helper_merge_admission_orders_receipts_canonically_batch8() -> None:
    res_a = _resolution(lane_id="lane-b")
    res_b = _resolution(lane_id="lane-a")
    decision = admit_helper_merge(
        resolutions=(res_a, res_b),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"balances:alice": 5},
            },
            "lane-b": {
                "receipts": [{"tx_id": "t2"}],
                "state_delta": {"balances:bob": 7},
            },
        },
    )
    assert decision.accepted is True
    expected_root = canonical_receipts_root(
        (
            {"tx_id": "t1"},
            {"tx_id": "t2"},
        )
    )
    assert decision.receipts_root == expected_root


def test_helper_merge_admission_rejects_duplicate_lane_resolution_batch8() -> None:
    res1 = _resolution(lane_id="lane-a")
    res2 = _resolution(lane_id="lane-a")
    decision = admit_helper_merge(
        resolutions=(res1, res2),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"balances:alice": 5},
            },
        },
    )
    assert decision.accepted is False
    assert decision.code == "duplicate_lane_resolution"
