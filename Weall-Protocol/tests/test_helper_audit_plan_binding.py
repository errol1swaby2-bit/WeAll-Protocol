from __future__ import annotations

from weall.runtime.helper_audit import build_lane_audit_plan, evaluate_lane_audit_plan
from weall.runtime.parallel_execution import LanePlan, canonical_lane_plan_fingerprint


def test_helper_audit_binds_to_plan_id_batch30() -> None:
    lane_plans = (
        LanePlan(lane_id="L1", helper_id="h1", txs=tuple(), tx_ids=("t1",), namespace_prefixes=("content:",)),
    )
    plan_id = canonical_lane_plan_fingerprint(lane_plans)
    audit_plan = build_lane_audit_plan(
        lane_plans=lane_plans,
        manifest_hash="mh",
        plan_id=plan_id,
        sample_percent=100,
    )
    assert audit_plan[0].plan_id == plan_id
    results = evaluate_lane_audit_plan(
        audit_plan=audit_plan,
        canonical_receipts_by_lane={"L1": []},
        helper_receipts_by_lane={"L1": []},
        expected_plan_id=plan_id,
    )
    assert results[0].plan_id == plan_id
    bad = evaluate_lane_audit_plan(
        audit_plan=audit_plan,
        canonical_receipts_by_lane={"L1": []},
        helper_receipts_by_lane={"L1": []},
        expected_plan_id="wrong-plan",
    )
    assert bad[0].fraud_suspected is True
    assert bad[0].reason == "plan_id_mismatch"
