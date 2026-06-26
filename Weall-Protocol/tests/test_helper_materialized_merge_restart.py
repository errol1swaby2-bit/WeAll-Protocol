from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from helper_audit_testkit import lane_setup
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_json,
    hash_ordered_strings,
    hash_receipts,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_merge import (
    HelperDeltaOp,
    MaterializedLaneResult,
    merge_materialized_lane_results,
)


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def _materialized_result(*, lane_plan, path: str, value: str, seed_byte: int, plan_id: str) -> MaterializedLaneResult:
    receipts = tuple({"tx_id": tx_id, "ok": True} for tx_id in lane_plan.tx_ids)
    delta_ops = (HelperDeltaOp(op="set", path=path, value=value),)
    read_set = tuple()
    write_set = (path,)
    seed = (bytes([seed_byte]) * 32).hex()
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            helper_id=str(lane_plan.helper_id or ""),
            validator_epoch=9,
            validator_set_hash="vhash",
            lane_id=str(lane_plan.lane_id),
            tx_ids=tuple(lane_plan.tx_ids),
            tx_order_hash=hash_json(list(lane_plan.tx_ids)),
            receipts_root=hash_receipts(receipts),
            write_set_hash=hash_ordered_strings(write_set),
            read_set_hash=hash_ordered_strings(read_set),
            lane_delta_hash=hash_json([op.to_json() for op in delta_ops]),
            namespace_hash=make_namespace_hash(lane_plan.namespace_prefixes),
            plan_id=plan_id,
        ),
        privkey=seed,
    )
    return MaterializedLaneResult(
        cert=cert,
        lane_plan=lane_plan,
        namespace_prefixes=tuple(lane_plan.namespace_prefixes),
        receipts=receipts,
        read_set=read_set,
        write_set=write_set,
        delta_ops=delta_ops,
    )


def test_materialized_merge_is_canonical_under_restart_order_changes_batch8() -> None:
    txs = [
        {"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
        {"tx_id": "i1", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
    ]
    lane_plans, plan_id = lane_setup(txs=txs)
    helper_lanes = tuple(sorted((plan for plan in lane_plans if str(plan.helper_id or "")), key=lambda item: item.lane_id))
    assert len(helper_lanes) == 2

    result_a = _materialized_result(lane_plan=helper_lanes[0], path="state/content/1", value="A", seed_byte=61, plan_id=plan_id)
    result_b = _materialized_result(lane_plan=helper_lanes[1], path="state/identity/alice", value="B", seed_byte=62, plan_id=plan_id)

    outcome1 = merge_materialized_lane_results(base_state={}, lane_results=[result_b, result_a])
    outcome2 = merge_materialized_lane_results(base_state={}, lane_results=[result_a, result_b])
    expected_lanes = tuple(sorted(plan.lane_id for plan in helper_lanes))
    assert outcome1.accepted_lane_ids == outcome2.accepted_lane_ids == expected_lanes
    assert outcome1.serialized_lane_ids == outcome2.serialized_lane_ids == ()
    assert outcome1.merged_state == outcome2.merged_state == {
        "state": {"content": {"1": "A"}, "identity": {"alice": "B"}}
    }


def test_materialized_merge_serializes_all_lanes_on_overlap_after_restart_batch8() -> None:
    txs = [
        {"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
        {"tx_id": "i1", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
    ]
    lane_plans, plan_id = lane_setup(txs=txs)
    helper_lanes = tuple(sorted((plan for plan in lane_plans if str(plan.helper_id or "")), key=lambda item: item.lane_id))
    assert len(helper_lanes) == 2

    result_a = _materialized_result(lane_plan=helper_lanes[0], path="shared/conflict", value="A", seed_byte=63, plan_id=plan_id)
    result_b = _materialized_result(lane_plan=helper_lanes[1], path="shared/conflict", value="B", seed_byte=64, plan_id=plan_id)

    outcome = merge_materialized_lane_results(base_state={"sentinel": True}, lane_results=[result_b, result_a])
    assert outcome.merged_state == {"sentinel": True}
    assert outcome.accepted_lane_ids == ()
    assert outcome.serialized_lane_ids == tuple(sorted(plan.lane_id for plan in helper_lanes))
