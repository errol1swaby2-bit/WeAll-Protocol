from __future__ import annotations

from weall.runtime.parallel_execution import (
    canonical_lane_plan_fingerprint,
    plan_parallel_execution,
    verify_lane_plan_equivalence,
    verify_vote_ready_helper_plan,
)


def test_verify_lane_plan_equivalence_rejects_cross_node_plan_mismatch_batch31() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    local_lane_plans = plan_parallel_execution(txs=txs, validators=["v1", "v2", "v3"], validator_set_hash="vhash-a", view=7, leader_id="v1")
    remote_lane_plans = plan_parallel_execution(txs=txs + [{"tx_id": "t2", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:2"]}], validators=["v1", "v2", "v3"], validator_set_hash="vhash-a", view=7, leader_id="v1")
    ok, reason = verify_lane_plan_equivalence(local_lane_plans=local_lane_plans, remote_lane_plans=remote_lane_plans)
    assert ok is False
    assert reason == "plan_id_mismatch"


def test_verify_vote_ready_helper_plan_accepts_matching_plan_id_batch31() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(txs=txs, validators=["v1", "v2", "v3"], validator_set_hash="vhash", view=7, leader_id="v1")
    advertised_plan_id = canonical_lane_plan_fingerprint(lane_plans)
    ok, reason = verify_vote_ready_helper_plan(local_lane_plans=lane_plans, advertised_plan_id=advertised_plan_id, helper_certificates={})
    assert ok is True
    assert reason == "ok"
