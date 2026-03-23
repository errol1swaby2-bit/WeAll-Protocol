from __future__ import annotations

from weall.runtime.helper_certificates import HelperExecutionCertificate
from weall.runtime.helper_merge_admission import admit_helper_merge
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution
from weall.runtime.parallel_execution import LanePlan


def test_helper_merge_rejects_certificate_plan_id_mismatch_batch31() -> None:
    lane_plan = LanePlan(lane_id="L1", helper_id="h1", txs=(), tx_ids=("t1",))
    cert = HelperExecutionCertificate(
        chain_id="c1",
        block_height=1,
        view=1,
        leader_id="v1",
        helper_id="h1",
        validator_epoch=1,
        validator_set_hash="vh",
        lane_id="L1",
        tx_ids=("t1",),
        tx_order_hash="order",
        receipts_root='bad',
        write_set_hash="writes",
        read_set_hash="reads",
        lane_delta_hash="deltahash",
        namespace_hash="ns",
        plan_id="wrong-plan",
    )
    resolution = HelperLaneResolution(lane_id="L1", helper_id="h1", mode="helper", certificate=cert)
    decision = admit_helper_merge(
        resolutions=(resolution,),
        lane_results_by_id={
            "L1": {
                "receipts": ({"tx_id": "t1"},),
                "state_delta": {"k": "v"},
                "tx_ids": ("t1",),
                "plan_id": "plan-1",
            }
        },
        lane_plan_by_id={"L1": lane_plan},
        expected_plan_id="plan-1",
    )
    assert decision.accepted is False
    assert decision.code == "certificate_plan_id_mismatch"
