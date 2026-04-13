from __future__ import annotations

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_ordered_strings,
    hash_receipts,
    make_namespace_hash,
)
from weall.runtime.helper_merge import (
    HelperDeltaOp,
    MaterializedLaneResult,
    detect_materialized_overlap,
    merge_materialized_lane_results,
    verify_materialized_lane_result,
)
from weall.runtime.parallel_execution import LanePlan


def _lane_plan(*, lane_id: str, helper_id: str, tx_ids: list[str]) -> LanePlan:
    return LanePlan(lane_id=lane_id, helper_id=helper_id, txs=tuple(), tx_ids=tuple(tx_ids))


def _materialized_result(
    *,
    lane_id: str,
    helper_id: str,
    tx_ids: list[str],
    namespace_prefixes: list[str],
    read_set: list[str],
    write_set: list[str],
    delta_ops: list[HelperDeltaOp],
    receipts: list[dict],
) -> MaterializedLaneResult:
    from weall.runtime.helper_merge import _hash_delta_ops

    cert = HelperExecutionCertificate(
        chain_id="merge-test",
        block_height=5,
        view=11,
        leader_id="@leader",
        helper_id=helper_id,
        validator_epoch=7,
        validator_set_hash="vhash",
        lane_id=lane_id,
        tx_ids=tuple(tx_ids),
        tx_order_hash="unused-in-batch5",
        receipts_root=hash_receipts(receipts),
        write_set_hash=hash_ordered_strings(write_set),
        read_set_hash=hash_ordered_strings(read_set),
        lane_delta_hash=_hash_delta_ops(delta_ops),
        namespace_hash=make_namespace_hash(namespace_prefixes),
        helper_signature="",
    )
    return MaterializedLaneResult(
        cert=cert,
        lane_plan=_lane_plan(lane_id=lane_id, helper_id=helper_id, tx_ids=tx_ids),
        namespace_prefixes=tuple(namespace_prefixes),
        receipts=tuple(receipts),
        read_set=tuple(read_set),
        write_set=tuple(write_set),
        delta_ops=tuple(delta_ops),
    )


def test_verify_materialized_lane_result_accepts_matching_hashes() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "hello"})],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    status = verify_materialized_lane_result(result)
    assert status.ok is True
    assert status.code == "ok"


def test_verify_materialized_lane_result_rejects_bad_delta_hash() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "hello"})],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    bad = MaterializedLaneResult(
        cert=HelperExecutionCertificate(**{**result.cert.to_json(), "lane_delta_hash": "bad"}),
        lane_plan=result.lane_plan,
        namespace_prefixes=result.namespace_prefixes,
        receipts=result.receipts,
        read_set=result.read_set,
        write_set=result.write_set,
        delta_ops=result.delta_ops,
    )
    status = verify_materialized_lane_result(bad)
    assert status.ok is False
    assert status.code == "lane_delta_hash_mismatch"


def test_detect_materialized_overlap_flags_conflict() -> None:
    left = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "a"})],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    right = _materialized_result(
        lane_id="PARALLEL_SOCIAL",
        helper_id="@helper-b",
        tx_ids=["tx-2"],
        namespace_prefixes=["social:"],
        read_set=["content:post:1"],
        write_set=["social:feed:@alice"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/social:feed:@alice", value=["tx-2"])],
        receipts=[{"tx_id": "tx-2", "ok": True}],
    )
    overlap, reason = detect_materialized_overlap([left, right])
    assert overlap is True
    assert reason == "read_write:content:post:1"


def test_merge_materialized_lane_results_is_deterministic_across_arrival_order() -> None:
    base_state = {"namespaced": {}}
    content = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "alpha"})],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    social = _materialized_result(
        lane_id="PARALLEL_SOCIAL",
        helper_id="@helper-b",
        tx_ids=["tx-2"],
        namespace_prefixes=["social:"],
        read_set=["social:feed:@alice"],
        write_set=["social:feed:@alice"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/social:feed:@alice", value=["tx-2"])],
        receipts=[{"tx_id": "tx-2", "ok": True}],
    )
    left = merge_materialized_lane_results(base_state=base_state, lane_results=[content, social])
    right = merge_materialized_lane_results(base_state=base_state, lane_results=[social, content])
    assert left.merged_state == right.merged_state
    assert left.accepted_lane_ids == right.accepted_lane_ids
    assert left.serialized_lane_ids == right.serialized_lane_ids


def test_merge_materialized_lane_results_matches_serial_replay_for_disjoint_lanes() -> None:
    base_state = {"namespaced": {}}
    content = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "alpha"})],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    social = _materialized_result(
        lane_id="PARALLEL_SOCIAL",
        helper_id="@helper-b",
        tx_ids=["tx-2"],
        namespace_prefixes=["social:"],
        read_set=["social:feed:@alice"],
        write_set=["social:feed:@alice"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/social:feed:@alice", value=["tx-2"])],
        receipts=[{"tx_id": "tx-2", "ok": True}],
    )

    merged = merge_materialized_lane_results(base_state=base_state, lane_results=[content, social])

    serial_state = {
        "namespaced": {
            "content:post:1": {"body": "alpha"},
            "social:feed:@alice": ["tx-2"],
        }
    }
    assert merged.merged_state == serial_state
    assert merged.accepted_lane_ids == ("PARALLEL_CONTENT", "PARALLEL_SOCIAL")
    assert merged.serialized_lane_ids == ()


def test_merge_materialized_lane_results_falls_back_on_overlap() -> None:
    base_state = {"namespaced": {"content:post:1": {"body": "old"}}}
    content = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "alpha"})],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    economy = _materialized_result(
        lane_id="PARALLEL_ECONOMY",
        helper_id="@helper-b",
        tx_ids=["tx-2"],
        namespace_prefixes=["economy:"],
        read_set=["content:post:1"],
        write_set=["economy:balance:@alice"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/economy:balance:@alice", value=5)],
        receipts=[{"tx_id": "tx-2", "ok": True}],
    )
    merged = merge_materialized_lane_results(base_state=base_state, lane_results=[content, economy])
    assert merged.merged_state == base_state
    assert merged.accepted_lane_ids == ()
    assert merged.serialized_lane_ids == ("PARALLEL_CONTENT", "PARALLEL_ECONOMY")


def test_verify_materialized_lane_result_rejects_delta_outside_declared_write_scope() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:2", value={"body": "hello"})],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    status = verify_materialized_lane_result(result)
    assert status.ok is False
    assert status.code == "delta_write_scope_mismatch"


def test_verify_materialized_lane_result_rejects_delta_outside_namespace_scope() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["social:feed:@alice"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/social:feed:@alice", value=["tx-1"])],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    status = verify_materialized_lane_result(result)
    assert status.ok is False
    assert status.code == "delta_namespace_scope_invalid"


def test_verify_materialized_lane_result_rejects_duplicate_delta_paths() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[
            HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "hello"}),
            HelperDeltaOp(op="delete", path="namespaced/content:post:1"),
        ],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    status = verify_materialized_lane_result(result)
    assert status.ok is False
    assert status.code == "delta_path_duplicate"
