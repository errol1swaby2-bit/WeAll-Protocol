from __future__ import annotations

from weall.runtime.parallel_execution import plan_parallel_execution


def _plan(*txs):
    return plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh",
        view=17,
        leader_id="v1",
    )


def test_inferred_parallel_path_splits_conflicting_same_subject_content_updates_batch35() -> None:
    left = {
        "tx_id": "t1",
        "tx_type": "CONTENT_POST_EDIT",
        "signer": "@alice",
        "payload": {"post_id": "shared-post", "content_id": "shared-post"},
        "state_prefixes": ["content:"],
    }
    right = {
        "tx_id": "t2",
        "tx_type": "CONTENT_POST_EDIT",
        "signer": "@bob",
        "payload": {"post_id": "shared-post", "content_id": "shared-post"},
        "state_prefixes": ["content:"],
    }

    plans = _plan(left, right)

    assert [plan.lane_id for plan in plans] == ["PARALLEL_CONTENT", "PARALLEL_CONTENT#1"]
    assert [plan.tx_ids for plan in plans] == [("t1",), ("t2",)]


def test_parallel_lane_assignment_fails_closed_when_access_scope_disagrees_with_declared_scope_batch35() -> None:
    tx = {
        "tx_id": "t1",
        "tx_type": "CONTENT_POST_CREATE",
        "signer": "@alice",
        "payload": {"post_id": "post-1", "content_id": "post-1"},
        "state_prefixes": ["economics:"],
    }

    plans = _plan(tx)

    assert len(plans) == 1
    assert plans[0].lane_id == "SERIAL"
    assert plans[0].helper_id is None
