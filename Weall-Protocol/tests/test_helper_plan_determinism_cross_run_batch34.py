from __future__ import annotations

from weall.runtime.parallel_execution import canonical_lane_plan_fingerprint, plan_parallel_execution


def _tx(tx_id: str, tx_type: str, prefixes: list[str]) -> dict:
    return {"tx_id": tx_id, "tx_type": tx_type, "state_prefixes": prefixes}


def test_plan_parallel_execution_is_stable_across_repeated_runs_batch34() -> None:
    txs = [
        _tx("t1", "CONTENT_CREATE", ["content:post:1"]),
        _tx("t2", "IDENTITY_UPDATE", ["identity:user:alice"]),
        _tx("t3", "SOCIAL_FOLLOW", ["social:follow:@alice:@bob"]),
    ]
    fingerprints = set()
    lane_summaries = set()
    for _ in range(8):
        lane_plans = plan_parallel_execution(
            txs=list(txs),
            validators=["v3", "v1", "v2", "v4"],
            validator_set_hash="vh-1",
            view=22,
            leader_id="v1",
        )
        fingerprints.add(canonical_lane_plan_fingerprint(lane_plans))
        lane_summaries.add(tuple((plan.lane_id, plan.helper_id, plan.tx_ids) for plan in lane_plans))
    assert len(fingerprints) == 1
    assert len(lane_summaries) == 1


def test_plan_parallel_execution_uses_validator_set_hash_without_destabilizing_shape_batch34() -> None:
    txs = [
        _tx("t1", "CONTENT_CREATE", ["content:post:1"]),
        _tx("t2", "IDENTITY_UPDATE", ["identity:user:alice"]),
    ]
    left = plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3", "v4", "v5"],
        validator_set_hash="vh-a",
        view=7,
        leader_id="v1",
    )
    right = plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3", "v4", "v5"],
        validator_set_hash="vh-b",
        view=7,
        leader_id="v1",
    )
    assert tuple(plan.lane_id for plan in left) == tuple(plan.lane_id for plan in right)
    assert all(plan.helper_candidates for plan in left)
    assert all(plan.helper_candidates for plan in right)
