from __future__ import annotations

from weall.runtime.helper_merge_admission import admit_helper_merge, canonical_receipts_root, canonical_state_delta_hash
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution
from weall.runtime.parallel_execution import LanePlan


class _Cert:
    def __init__(self, receipts_root: str = "", lane_delta_hash: str = "", tx_ids=()) -> None:
        self.receipts_root = receipts_root
        self.lane_delta_hash = lane_delta_hash
        self.tx_ids = tuple(tx_ids)


def test_helper_merge_admission_rejects_plan_id_mismatch_batch28() -> None:
    decision = admit_helper_merge(
        resolutions=(HelperLaneResolution(lane_id="lane-a", helper_id="h1", mode="helper", certificate=None),),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"k": 1},
                "plan_id": "wrong-plan",
            }
        },
        expected_plan_id="expected-plan",
    )
    assert decision.accepted is False
    assert decision.code == "plan_id_mismatch"


def test_helper_merge_admission_rejects_lane_tx_ids_mismatch_batch28() -> None:
    cert = _Cert(receipts_root=canonical_receipts_root([{"tx_id": "t1"}]), lane_delta_hash=canonical_state_delta_hash({"k": 1}), tx_ids=("t1",))
    decision = admit_helper_merge(
        resolutions=(HelperLaneResolution(lane_id="lane-a", helper_id="h1", mode="helper", certificate=cert),),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"k": 1},
                "tx_ids": ["t2"],
            }
        },
    )
    assert decision.accepted is False
    assert decision.code == "lane_tx_ids_mismatch"


def test_helper_merge_admission_accepts_with_lane_plan_binding_batch28() -> None:
    plan = LanePlan(lane_id="lane-a", helper_id="h1", txs=(), tx_ids=("t1",))
    cert = _Cert(receipts_root=canonical_receipts_root([{"tx_id": "t1"}]), lane_delta_hash=canonical_state_delta_hash({"k": 1}), tx_ids=("t1",))
    decision = admit_helper_merge(
        resolutions=(HelperLaneResolution(lane_id="lane-a", helper_id="h1", mode="helper", certificate=cert),),
        lane_results_by_id={
            "lane-a": {
                "receipts": [{"tx_id": "t1"}],
                "state_delta": {"k": 1},
            }
        },
        lane_plan_by_id={"lane-a": plan},
    )
    assert decision.accepted is True
    assert decision.plan_id
