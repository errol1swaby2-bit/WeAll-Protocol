from weall.runtime.parallel_execution import lane_base_id, plan_parallel_execution


def _tx(tx_id: str, tx_type: str, read_set=None, write_set=None):
    return {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "read_set": list(read_set or []),
        "write_set": list(write_set or []),
    }


def test_plan_parallel_execution_splits_conflicting_same_domain_lanes() -> None:
    txs = [
        _tx("t1", "CONTENT_POST_CREATE", read_set=["identity:user:@alice"], write_set=["content:post:1"]),
        _tx("t2", "CONTENT_POST_UPDATE", read_set=["content:post:1"], write_set=["content:post:1"]),
        _tx("t3", "CONTENT_POST_CREATE", read_set=["identity:user:@bob"], write_set=["content:post:2"]),
    ]
    plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vh",
        view=9,
        leader_id="v1",
    )
    assert [p.tx_ids for p in plans] == [("t1",), ("t2",), ("t3",)]
    assert [lane_base_id(p.lane_id) for p in plans] == ["CONTENT", "CONTENT", "CONTENT"]
    assert plans[0].lane_id == "CONTENT"
    assert plans[1].lane_id == "CONTENT#1"
    assert plans[2].lane_id == "CONTENT#2"


def test_plan_parallel_execution_keeps_non_conflicting_contiguous_group_together() -> None:
    txs = [
        _tx("a1", "CONTENT_POST_CREATE", read_set=["identity:user:@a"], write_set=["content:post:1"]),
        _tx("a2", "CONTENT_POST_CREATE", read_set=["identity:user:@b"], write_set=["content:post:2"]),
    ]
    plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vh",
        view=5,
        leader_id="v1",
    )
    assert len(plans) == 1
    assert plans[0].lane_id == "CONTENT"
    assert plans[0].tx_ids == ("a1", "a2")
