from __future__ import annotations

from weall.runtime.helper_merge_admission import admit_helper_merge
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution
from weall.runtime.parallel_execution import LanePlan


def test_helper_merge_rejects_cross_lane_tx_id_conflict_batch5() -> None:
    lane_plan_a = LanePlan(lane_id="L1", helper_id="h1", txs=(), tx_ids=("t1",))
    lane_plan_b = LanePlan(lane_id="L2", helper_id="h2", txs=(), tx_ids=("t1",))
    resolutions = (
        HelperLaneResolution(lane_id="L1", helper_id="h1", mode="helper", certificate=None),
        HelperLaneResolution(lane_id="L2", helper_id="h2", mode="helper", certificate=None),
    )
    decision = admit_helper_merge(
        resolutions=resolutions,
        lane_results_by_id={
            "L1": {"receipts": ({"tx_id": "t1"},), "state_delta": {"k1": "v1"}, "tx_ids": ("t1",)},
            "L2": {"receipts": ({"tx_id": "t1"},), "state_delta": {"k2": "v2"}, "tx_ids": ("t1",)},
        },
        lane_plan_by_id={"L1": lane_plan_a, "L2": lane_plan_b},
    )
    assert decision.accepted is False
    assert decision.code == "cross_lane_tx_id_conflict"



def test_helper_merge_rejects_cross_lane_receipt_tx_id_conflict_batch5() -> None:
    resolutions = (
        HelperLaneResolution(lane_id="L1", helper_id="h1", mode="helper", certificate=None),
        HelperLaneResolution(lane_id="L2", helper_id="h2", mode="helper", certificate=None),
    )
    decision = admit_helper_merge(
        resolutions=resolutions,
        lane_results_by_id={
            "L1": {"receipts": ({"tx_id": "t1"},), "state_delta": {"k1": "v1"}},
            "L2": {"receipts": ({"tx_id": "t1"},), "state_delta": {"k2": "v2"}},
        },
    )
    assert decision.accepted is False
    assert decision.code == "cross_lane_receipt_tx_id_conflict"



def test_helper_merge_rejects_duplicate_lane_receipt_tx_ids_batch5() -> None:
    lane_plan = LanePlan(lane_id="L1", helper_id="h1", txs=(), tx_ids=("t1", "t2"))
    resolution = HelperLaneResolution(lane_id="L1", helper_id="h1", mode="helper", certificate=None)
    decision = admit_helper_merge(
        resolutions=(resolution,),
        lane_results_by_id={
            "L1": {
                "receipts": ({"tx_id": "t1"}, {"tx_id": "t1"}),
                "state_delta": {"k": "v"},
                "tx_ids": ("t1", "t1"),
            }
        },
        lane_plan_by_id={"L1": lane_plan},
    )
    assert decision.accepted is False
    assert decision.code == "duplicate_lane_receipt_tx_id"
