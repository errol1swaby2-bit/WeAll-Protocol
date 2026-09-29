from __future__ import annotations

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_json,
    hash_ordered_strings,
    hash_receipts,
    make_namespace_hash,
)
from weall.runtime.helper_merge import (
    HelperDeltaOp,
    MaterializedLaneResult,
    detect_materialized_overlap,
)
from weall.runtime.helper_merge import (
    merge_materialized_lane_results as _merge_materialized_lane_results,
)
from weall.runtime.helper_merge import (
    verify_materialized_lane_result as _verify_materialized_lane_result,
)
from weall.runtime.parallel_execution import LanePlan
from weall.runtime.read_write_sets import TxAccessSet


def _lane_plan(
    *,
    lane_id: str,
    helper_id: str,
    tx_ids: list[str],
    namespace_prefixes: list[str],
    read_set: list[str],
    write_set: list[str],
) -> LanePlan:
    access_sets = []
    for index, tx_id in enumerate(tx_ids):
        access_sets.append(
            TxAccessSet(
                tx_id=tx_id,
                lane_hint="CONTENT",
                reads=tuple(read_set) if index == 0 else tuple(),
                writes=tuple(write_set) if index == 0 else tuple(),
                fail_closed_serial=False,
                family="CONTENT",
                barrier_class="SCOPED_PARALLEL",
            )
        )
    return LanePlan(
        lane_id=lane_id,
        helper_id=helper_id,
        txs=tuple(),
        tx_ids=tuple(tx_ids),
        access_sets=tuple(access_sets),
        namespace_prefixes=tuple(namespace_prefixes),
    )


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
        tx_order_hash=hash_json(list(tx_ids)),
        receipts_root=hash_receipts(receipts),
        write_set_hash=hash_ordered_strings(sorted(set(write_set))),
        read_set_hash=hash_ordered_strings(sorted(set(read_set))),
        lane_delta_hash=_hash_delta_ops(delta_ops),
        namespace_hash=make_namespace_hash(namespace_prefixes),
        helper_signature="",
    )
    lane_plan = _lane_plan(
        lane_id=lane_id,
        helper_id=helper_id,
        tx_ids=tx_ids,
        namespace_prefixes=namespace_prefixes,
        read_set=read_set,
        write_set=write_set,
    )
    return MaterializedLaneResult(
        cert=cert,
        lane_plan=lane_plan,
        namespace_prefixes=tuple(namespace_prefixes),
        receipts=tuple(receipts),
        read_set=tuple(read_set),
        write_set=tuple(write_set),
        delta_ops=tuple(delta_ops),
    )


def _verify(result: MaterializedLaneResult):
    return _verify_materialized_lane_result(
        result,
        expected_lane_plan=result.lane_plan,
        accepted_certificate=result.cert,
    )


def _merge(*, base_state, lane_results):
    results = list(lane_results)
    return _merge_materialized_lane_results(
        base_state=base_state,
        lane_results=results,
        lane_plans=tuple(result.lane_plan for result in results),
        accepted_certificates={result.cert.lane_id: result.cert for result in results},
    )


def test_verify_materialized_lane_result_accepts_matching_hashes() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[
            HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "hello"})
        ],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    status = _verify(result)
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
        delta_ops=[
            HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "hello"})
        ],
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
    status = _verify(bad)
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
        delta_ops=[
            HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "alpha"})
        ],
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
    left = _merge(base_state=base_state, lane_results=[content, social])
    right = _merge(base_state=base_state, lane_results=[social, content])
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
        delta_ops=[
            HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "alpha"})
        ],
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

    merged = _merge(base_state=base_state, lane_results=[content, social])

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
        delta_ops=[
            HelperDeltaOp(op="set", path="namespaced/content:post:1", value={"body": "alpha"})
        ],
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
    merged = _merge(base_state=base_state, lane_results=[content, economy])
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
        delta_ops=[
            HelperDeltaOp(op="set", path="namespaced/content:post:2", value={"body": "hello"})
        ],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    status = _verify(result)
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
    status = _verify(result)
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
    status = _verify(result)
    assert status.ok is False
    assert status.code == "delta_path_duplicate"


def test_verify_materialized_lane_result_rejects_wrong_helper_even_when_self_consistent() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    bad_cert = HelperExecutionCertificate(**{**result.cert.to_json(), "helper_id": "@attacker"})
    bad = MaterializedLaneResult(
        cert=bad_cert,
        lane_plan=result.lane_plan,
        namespace_prefixes=result.namespace_prefixes,
        receipts=result.receipts,
        read_set=result.read_set,
        write_set=result.write_set,
        delta_ops=result.delta_ops,
    )
    status = _verify_materialized_lane_result(
        bad,
        expected_lane_plan=result.lane_plan,
        accepted_certificate=bad_cert,
    )
    assert status.ok is False
    assert status.code == "helper_id_mismatch"


def test_verify_materialized_lane_result_rejects_widened_write_scope() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    widened = ("content:post:1", "content:post:2")
    widened_cert = HelperExecutionCertificate(
        **{**result.cert.to_json(), "write_set_hash": hash_ordered_strings(widened)}
    )
    bad = MaterializedLaneResult(
        cert=widened_cert,
        lane_plan=result.lane_plan,
        namespace_prefixes=result.namespace_prefixes,
        receipts=result.receipts,
        read_set=result.read_set,
        write_set=widened,
        delta_ops=result.delta_ops,
    )
    status = _verify_materialized_lane_result(
        bad,
        expected_lane_plan=result.lane_plan,
        accepted_certificate=widened_cert,
    )
    assert status.ok is False
    assert status.code == "write_set_plan_mismatch"


def test_verify_materialized_lane_result_rejects_hidden_write_by_scope_omission() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    omitted: tuple[str, ...] = tuple()
    omitted_cert = HelperExecutionCertificate(
        **{**result.cert.to_json(), "write_set_hash": hash_ordered_strings(omitted)}
    )
    bad = MaterializedLaneResult(
        cert=omitted_cert,
        lane_plan=result.lane_plan,
        namespace_prefixes=result.namespace_prefixes,
        receipts=result.receipts,
        read_set=result.read_set,
        write_set=omitted,
        delta_ops=tuple(),
    )
    status = _verify_materialized_lane_result(
        bad,
        expected_lane_plan=result.lane_plan,
        accepted_certificate=omitted_cert,
    )
    assert status.ok is False
    assert status.code == "write_set_plan_mismatch"


def test_verify_materialized_lane_result_rejects_namespace_widening() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    widened = ("content:", "social:")
    widened_cert = HelperExecutionCertificate(
        **{**result.cert.to_json(), "namespace_hash": make_namespace_hash(widened)}
    )
    bad = MaterializedLaneResult(
        cert=widened_cert,
        lane_plan=result.lane_plan,
        namespace_prefixes=widened,
        receipts=result.receipts,
        read_set=result.read_set,
        write_set=result.write_set,
        delta_ops=result.delta_ops,
    )
    status = _verify_materialized_lane_result(
        bad,
        expected_lane_plan=result.lane_plan,
        accepted_certificate=widened_cert,
    )
    assert status.ok is False
    assert status.code == "namespace_plan_mismatch"


def test_verify_materialized_lane_result_rejects_receipt_order_mismatch() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1", "tx-2"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
        receipts=[{"tx_id": "tx-1", "ok": True}, {"tx_id": "tx-2", "ok": True}],
    )
    reversed_receipts = tuple(reversed(result.receipts))
    reversed_cert = HelperExecutionCertificate(
        **{**result.cert.to_json(), "receipts_root": hash_receipts(reversed_receipts)}
    )
    bad = MaterializedLaneResult(
        cert=reversed_cert,
        lane_plan=result.lane_plan,
        namespace_prefixes=result.namespace_prefixes,
        receipts=reversed_receipts,
        read_set=result.read_set,
        write_set=result.write_set,
        delta_ops=result.delta_ops,
    )
    status = _verify_materialized_lane_result(
        bad,
        expected_lane_plan=result.lane_plan,
        accepted_certificate=reversed_cert,
    )
    assert status.ok is False
    assert status.code == "receipt_tx_order_mismatch"


def test_verify_materialized_lane_result_requires_exact_accepted_certificate() -> None:
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    different_cert = HelperExecutionCertificate(
        **{**result.cert.to_json(), "lane_delta_hash": "different"}
    )
    bad = MaterializedLaneResult(
        cert=different_cert,
        lane_plan=result.lane_plan,
        namespace_prefixes=result.namespace_prefixes,
        receipts=result.receipts,
        read_set=result.read_set,
        write_set=result.write_set,
        delta_ops=result.delta_ops,
    )
    status = _verify_materialized_lane_result(
        bad,
        expected_lane_plan=result.lane_plan,
        accepted_certificate=result.cert,
    )
    assert status.ok is False
    assert status.code == "accepted_certificate_mismatch"


def test_merge_materialized_lane_results_fails_closed_on_duplicate_lane_result() -> None:
    base_state = {"sentinel": True}
    result = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
        receipts=[{"tx_id": "tx-1", "ok": True}],
    )
    outcome = _merge_materialized_lane_results(
        base_state=base_state,
        lane_results=[result, result],
        lane_plans=(result.lane_plan,),
        accepted_certificates={result.cert.lane_id: result.cert},
    )
    assert outcome.merged_state == base_state
    assert outcome.accepted_lane_ids == ()
    assert outcome.serialized_lane_ids == ("PARALLEL_CONTENT",)


def test_merge_materialized_lane_results_marks_missing_expected_lane_serial() -> None:
    content = _materialized_result(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-a",
        tx_ids=["tx-1"],
        namespace_prefixes=["content:"],
        read_set=["content:post:1"],
        write_set=["content:post:1"],
        delta_ops=[HelperDeltaOp(op="set", path="namespaced/content:post:1", value="ok")],
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
    outcome = _merge_materialized_lane_results(
        base_state={"namespaced": {}},
        lane_results=[content],
        lane_plans=(content.lane_plan, social.lane_plan),
        accepted_certificates={
            content.cert.lane_id: content.cert,
            social.cert.lane_id: social.cert,
        },
    )
    assert outcome.accepted_lane_ids == ("PARALLEL_CONTENT",)
    assert outcome.serialized_lane_ids == ("PARALLEL_SOCIAL",)
