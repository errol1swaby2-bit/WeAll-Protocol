from weall.runtime.conflict_lanes import plan_conflict_lanes


def _tx(tx_id: str, tx_type: str, reads=None, writes=None):
    tx = {"tx_id": tx_id, "tx_type": tx_type}
    if reads is not None:
        tx["read_set"] = reads
    if writes is not None:
        tx["write_set"] = writes
    return tx


def test_disjoint_writes_share_lane() -> None:
    plan = plan_conflict_lanes(
        [
            _tx("t1", "CONTENT_POST_CREATE", writes=["content:post:1"]),
            _tx("t2", "CONTENT_POST_CREATE", writes=["content:post:2"]),
        ]
    )
    assert len(plan.lanes) == 1
    assert plan.lanes[0].tx_ids == ("t1", "t2")


def test_write_write_conflict_splits_lane() -> None:
    plan = plan_conflict_lanes(
        [
            _tx("t1", "CONTENT_POST_CREATE", writes=["content:post:1"]),
            _tx("t2", "CONTENT_POST_EDIT", writes=["content:post:1"]),
        ]
    )
    assert len(plan.lanes) == 2
    assert plan.lanes[0].tx_ids == ("t1",)
    assert plan.lanes[1].tx_ids == ("t2",)


def test_read_write_conflict_splits_lane() -> None:
    plan = plan_conflict_lanes(
        [
            _tx("t1", "CONTENT_POST_VIEW", reads=["content:post:1"]),
            _tx("t2", "CONTENT_POST_EDIT", writes=["content:post:1"]),
        ]
    )
    assert len(plan.lanes) == 2


def test_fail_closed_unknown_tx_is_serialized() -> None:
    plan = plan_conflict_lanes([
        {"tx_id": "t1", "tx_type": "MYSTERY_TX"},
        _tx("t2", "CONTENT_POST_CREATE", writes=["content:post:2"]),
    ])
    assert plan.lanes[0].serial_only is True
    assert plan.serialized_tx_ids == ("t1",)


def test_plan_is_stable_for_same_input() -> None:
    txs = [
        _tx("t1", "CONTENT_POST_CREATE", writes=["content:post:1"]),
        _tx("t2", "CONTENT_POST_CREATE", writes=["content:post:2"]),
        _tx("t3", "CONTENT_POST_EDIT", writes=["content:post:1"]),
    ]
    p1 = plan_conflict_lanes(txs)
    p2 = plan_conflict_lanes(txs)
    assert p1 == p2
