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


def test_content_posts_with_distinct_subjects_share_one_parallel_lane_batch6() -> None:
    plans = _plan(
        build_helper_conflict_probe_tx("CONTENT_POST_CREATE", seed="1"),
        build_helper_conflict_probe_tx("CONTENT_POST_CREATE", seed="2"),
    )
    assert len(plans) == 1
    assert lane_base_id(plans[0].lane_id) == "CONTENT"
    assert plans[0].tx_ids == ("content_post_create-1", "content_post_create-2")


def test_content_updates_to_same_post_split_into_distinct_lanes_batch6() -> None:
    left = build_helper_conflict_probe_tx("CONTENT_POST_EDIT", seed="1", payload_overrides={"post_id": "post-shared", "content_id": "post-shared"})
    right = build_helper_conflict_probe_tx("CONTENT_POST_EDIT", seed="2", payload_overrides={"post_id": "post-shared", "content_id": "post-shared"})
    plans = _plan(left, right)
    assert len(plans) == 2
    assert [lane_base_id(plan.lane_id) for plan in plans] == ["CONTENT", "CONTENT"]
    assert plans[0].lane_id == "CONTENT"
    assert plans[1].lane_id == "CONTENT#1"


def test_balance_transfers_with_disjoint_accounts_share_parallel_economics_lane_batch6() -> None:
    one = build_helper_conflict_probe_tx("BALANCE_TRANSFER", seed="1", payload_overrides={"from_account_id": "acct-a", "to_account_id": "acct-b"})
    two = build_helper_conflict_probe_tx("BALANCE_TRANSFER", seed="2", payload_overrides={"from_account_id": "acct-c", "to_account_id": "acct-d"})
    plans = _plan(one, two)
    assert len(plans) == 1
    assert lane_base_id(plans[0].lane_id) == "ECONOMICS"


def test_balance_transfers_with_overlapping_account_split_batch6() -> None:
    one = build_helper_conflict_probe_tx("BALANCE_TRANSFER", seed="1", payload_overrides={"from_account_id": "acct-a", "to_account_id": "acct-b"})
    two = build_helper_conflict_probe_tx("BALANCE_TRANSFER", seed="2", payload_overrides={"from_account_id": "acct-b", "to_account_id": "acct-c"})
    plans = _plan(one, two)
    assert len(plans) == 2
    assert [lane_base_id(plan.lane_id) for plan in plans] == ["ECONOMICS", "ECONOMICS"]


def test_group_membership_requests_for_distinct_groups_share_governance_lane_batch6() -> None:
    one = build_helper_conflict_probe_tx("GROUP_MEMBERSHIP_REQUEST", seed="1", payload_overrides={"group_id": "group-a", "member_id": "acct-a"})
    two = build_helper_conflict_probe_tx("GROUP_MEMBERSHIP_REQUEST", seed="2", payload_overrides={"group_id": "group-b", "member_id": "acct-b"})
    plans = _plan(one, two)
    assert len(plans) == 1
    assert lane_base_id(plans[0].lane_id) == "GOVERNANCE"


def test_group_treasury_policy_same_group_splits_with_governance_authority_key_batch6() -> None:
    one = build_helper_conflict_probe_tx("GROUP_TREASURY_POLICY_SET", seed="1", payload_overrides={"group_id": "group-shared"})
    two = build_helper_conflict_probe_tx("GROUP_TREASURY_POLICY_SET", seed="2", payload_overrides={"group_id": "group-shared"})
    plans = _plan(one, two)
    assert len(plans) == 2
    assert [lane_base_id(plan.lane_id) for plan in plans] == ["GOVERNANCE", "GOVERNANCE"]


def test_validator_set_update_remains_serial_global_barrier_batch6() -> None:
    plans = _plan(
        build_helper_conflict_probe_tx("CONTENT_POST_CREATE", seed="1"),
        build_helper_conflict_probe_tx("VALIDATOR_SET_UPDATE", seed="2"),
        build_helper_conflict_probe_tx("CONTENT_POST_CREATE", seed="3"),
    )
    serial = [plan for plan in plans if lane_base_id(plan.lane_id) == "SERIAL"]
    assert len(serial) == 1
    assert serial[0].tx_ids == ("validator_set_update-2",)


def test_notification_subscriptions_for_distinct_topics_share_social_lane_batch6() -> None:
    one = build_helper_conflict_probe_tx("NOTIFICATION_SUBSCRIBE", seed="1", payload_overrides={"account_id": "acct-a", "topic": "topic-a"})
    two = build_helper_conflict_probe_tx("NOTIFICATION_SUBSCRIBE", seed="2", payload_overrides={"account_id": "acct-b", "topic": "topic-b"})
    plans = _plan(one, two)
    assert len(plans) == 1
    assert lane_base_id(plans[0].lane_id) == "SOCIAL"
