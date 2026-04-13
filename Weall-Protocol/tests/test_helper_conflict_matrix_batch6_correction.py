from __future__ import annotations

from weall.runtime.parallel_execution import lane_base_id, plan_parallel_execution
from weall.runtime.tx_conflict_audit_samples import build_helper_conflict_probe_tx

VALIDATORS = ["v1", "v2", "v3", "v4"]


def _plan(*txs):
    return plan_parallel_execution(
        txs=list(txs),
        validators=VALIDATORS,
        validator_set_hash="vh",
        view=11,
        leader_id="v1",
    )


def test_group_treasury_policy_same_group_splits_with_governance_authority_key_batch6_correction() -> None:
    one = build_helper_conflict_probe_tx("GROUP_TREASURY_POLICY_SET", seed="1", payload_overrides={"group_id": "group-shared"})
    two = build_helper_conflict_probe_tx("GROUP_TREASURY_POLICY_SET", seed="2", payload_overrides={"group_id": "group-shared"})
    plans = _plan(one, two)
    assert len(plans) == 2
    assert [lane_base_id(plan.lane_id) for plan in plans] == ["GOVERNANCE", "GOVERNANCE"]
