from __future__ import annotations

from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_event_driver import HelperEvent
from weall.runtime.helper_proposal_loop import HelperProposalCycleInput, run_helper_proposal_loop
from weall.runtime.parallel_execution import LanePlan, canonical_lane_plan_fingerprint


def test_helper_proposal_loop_surfaces_plan_id_batch30() -> None:
    lane_plans = (
        LanePlan(lane_id="L1", helper_id="h1", txs=tuple(), tx_ids=("t1",)),
    )
    expected_plan_id = canonical_lane_plan_fingerprint(lane_plans)
    summary = run_helper_proposal_loop(
        base_context=HelperDispatchContext(
            chain_id="c1",
            block_height=10,
            view=4,
            leader_id="v1",
            validator_epoch=3,
            validator_set_hash="vh",
        ),
        lane_plans=lane_plans,
        cycles=(
            HelperProposalCycleInput(
                block_height=10,
                events=(HelperEvent(kind="start", started_ms=1),),
                lane_results_by_id={},
            ),
        ),
    )
    assert summary.results[0].plan_id == expected_plan_id
