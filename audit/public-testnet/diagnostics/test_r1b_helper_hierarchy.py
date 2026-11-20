"""R1B / TN-052: diagnostic probes against unmodified runtime.

These fixtures exercise real planner and merge functions. They deliberately
construct local plans and already-accepted certificates; they do not prove
authenticated network admission or consensus reachability.
"""
from __future__ import annotations

import copy

import pytest

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_ordered_strings,
    hash_receipts,
    make_namespace_hash,
    make_tx_order_hash,
)
from weall.runtime.helper_merge import (
    HelperDeltaOp,
    MaterializedLaneResult,
    _hash_delta_ops,
    apply_materialized_delta_ops,
    detect_materialized_overlap,
    merge_materialized_lane_results,
    verify_materialized_lane_result,
)
from weall.runtime.parallel_execution import LanePlan, _access_conflicts, plan_parallel_execution
from weall.runtime.read_write_sets import TxAccessSet


def access(tx_id, reads=(), writes=()):
    return TxAccessSet(
        tx_id=tx_id,
        lane_hint="PARALLEL_CONTENT",
        reads=tuple(reads),
        writes=tuple(writes),
        fail_closed_serial=False,
        family="CONTENT",
        barrier_class="SCOPED_PARALLEL",
    )


CASES = [
    ((), ("accounts/x",), (), ("accounts/x",), True),
    ((), ("accounts/x",), (), ("accounts/x/balance",), True),
    (("accounts/x",), (), (), ("accounts/x/balance",), True),
    ((), ("accounts/x",), ("accounts/x/balance",), (), True),
    ((), ("accounts//x/",), (), ("accounts/x",), True),
    ((), ("accounts/x/balance",), (), ("accounts/x/reputation",), False),
    (("accounts/x",), (), ("accounts/x/balance",), (), False),
    ((), ("accounts/x",), (), ("accounts/xx",), False),
    ((), ("accounts/X",), (), ("accounts/x",), False),
    ((), ("content:post:1",), (), ("content:post:10",), False),
]


@pytest.mark.parametrize("ar,aw,br,bw,expected", CASES)
def test_planner_conflict_predicate(ar, aw, br, bw, expected):
    left, right = access("t1", ar, aw), access("t2", br, bw)
    assert _access_conflicts([left], right) is expected
    assert _access_conflicts([right], left) is expected


def materialized(lane_id, tx_id, reads, writes, ops=()):
    scope = access(tx_id, reads, writes)
    helper_id = "@helper-" + tx_id
    namespaces = ("accounts", "content:")
    plan = LanePlan(
        lane_id=lane_id,
        helper_id=helper_id,
        txs=(),
        tx_ids=(tx_id,),
        access_sets=(scope,),
        namespace_prefixes=namespaces,
    )
    receipts = ({"tx_id": tx_id, "ok": True},)
    cert = HelperExecutionCertificate(
        chain_id="audit-fixture",
        block_height=5,
        view=11,
        leader_id="@leader",
        helper_id=helper_id,
        validator_epoch=7,
        validator_set_hash="fixture-vhash",
        lane_id=lane_id,
        tx_ids=(tx_id,),
        tx_order_hash=make_tx_order_hash((tx_id,)),
        receipts_root=hash_receipts(list(receipts)),
        write_set_hash=hash_ordered_strings(sorted(set(writes))),
        read_set_hash=hash_ordered_strings(sorted(set(reads))),
        lane_delta_hash=_hash_delta_ops(tuple(ops)),
        namespace_hash=make_namespace_hash(namespaces),
        helper_signature="",
    )
    result = MaterializedLaneResult(
        cert=cert,
        lane_plan=plan,
        namespace_prefixes=namespaces,
        receipts=receipts,
        read_set=tuple(reads),
        write_set=tuple(writes),
        delta_ops=tuple(ops),
    )
    status = verify_materialized_lane_result(
        result, expected_lane_plan=plan, accepted_certificate=cert
    )
    assert status.ok, f"invalid test fixture: {status.code}"
    return result


@pytest.mark.parametrize("ar,aw,br,bw,expected", CASES)
def test_materialized_conflict_predicate(ar, aw, br, bw, expected):
    a = materialized("PARALLEL_CONTENT", "t1", ar, aw)
    b = materialized("PARALLEL_CONTENT#1", "t2", br, bw)
    assert detect_materialized_overlap([a, b])[0] is expected
    assert detect_materialized_overlap([b, a])[0] is expected


def merge(base, results):
    return merge_materialized_lane_results(
        base_state=base,
        lane_results=results,
        lane_plans=tuple(item.lane_plan for item in results),
        accepted_certificates={item.cert.lane_id: item.cert for item in results},
    )


@pytest.mark.parametrize("op", ["set", "delete"])
def test_parent_child_merge_falls_back(op):
    base = {"accounts": {"x": {"balance": 10, "reputation": 3}}}
    before = copy.deepcopy(base)
    parent = HelperDeltaOp(op=op, path="accounts/x", value={"balance": 20})
    child = HelperDeltaOp(op="set", path="accounts/x/balance", value=99)
    a = materialized("PARALLEL_CONTENT", "t1", (), ("accounts/x",), (parent,))
    b = materialized("PARALLEL_CONTENT#1", "t2", (), ("accounts/x/balance",), (child,))
    # Demonstrate serial-order sensitivity without claiming a network exploit.
    assert apply_materialized_delta_ops(apply_materialized_delta_ops(base, [parent]), [child]) != (
        apply_materialized_delta_ops(apply_materialized_delta_ops(base, [child]), [parent])
    )
    for results in ([a, b], [b, a]):
        outcome = merge(base, results)
        assert outcome.merged_state == before
        assert outcome.accepted_lane_ids == ()
        assert outcome.serialized_lane_ids == tuple(sorted([a.cert.lane_id, b.cert.lane_id]))
    assert base == before


def test_disjoint_delta_merge_matches_serial_in_both_orders():
    base = {"accounts": {"x": {"balance": 10, "reputation": 3}}}
    x = HelperDeltaOp(op="set", path="accounts/x/balance", value=20)
    y = HelperDeltaOp(op="set", path="accounts/x/reputation", value=4)
    a = materialized("PARALLEL_CONTENT", "t1", (), ("accounts/x/balance",), (x,))
    b = materialized("PARALLEL_CONTENT#1", "t2", (), ("accounts/x/reputation",), (y,))
    serial = apply_materialized_delta_ops(apply_materialized_delta_ops(base, [x]), [y])
    for results in ([a, b], [b, a]):
        result = merge(base, results)
        assert result.merged_state == serial
        assert len(result.accepted_lane_ids) == 2
        assert result.serialized_lane_ids == ()


def explicit_tx(tx_id, path):
    return {
        "tx_id": tx_id,
        "tx_type": "CONTENT_POST_EDIT",
        "signer": "@alice",
        "payload": {"post_id": "fixture", "content_id": "fixture"},
        "family": "CONTENT",
        "barrier_class": "SCOPED_PARALLEL",
        "read_set": [],
        "write_set": [path],
        "state_prefixes": ["content:"],
    }


@pytest.mark.parametrize("second,conflict", [("content:post:1/body", True), ("content:post:2", False)])
def test_explicit_planner_groups(second, conflict):
    txs = [explicit_tx("t1", "content:post:1"), explicit_tx("t2", second)]
    plans = plan_parallel_execution(
        txs=txs, validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="fixture", view=17, leader_id="v1",
    )
    assert [tx for p in plans for tx in p.tx_ids] == ["t1", "t2"]
    # This fixture tests the explicit access path, not live canonical derivation.
    parallel = [p for p in plans if p.helper_id and p.lane_id != "SERIAL"]
    assert parallel, "fixture did not reach the parallel planner"
    shared = any({"t1", "t2"}.issubset(set(p.tx_ids)) for p in parallel)
    assert shared is (not conflict)
