#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_ordered_strings,
    hash_receipts,
    hash_state_delta_ops,
    make_namespace_hash,
    make_tx_order_hash,
)
from weall.runtime.helper_merge import (
    HelperDeltaOp,
    MaterializedLaneResult,
    merge_materialized_lane_results,
    verify_materialized_lane_result,
)
from weall.runtime.parallel_execution import LanePlan
from weall.runtime.read_write_sets import TxAccessSet

Json = dict[str, Any]


def _materialized_result(*, value: str) -> MaterializedLaneResult:
    tx_ids = ("tx:helper-b593-1",)
    namespace_prefixes = ("content:",)
    read_set = ("content:post:1",)
    write_set = ("content:post:1",)
    receipts = ({"tx_id": tx_ids[0], "ok": True},)
    delta_ops = (
        HelperDeltaOp(
            op="set",
            path="namespaced/content:post:1",
            value={"body": value},
        ),
    )
    lane = LanePlan(
        lane_id="PARALLEL_CONTENT",
        helper_id="@helper-b593",
        txs=tuple(),
        tx_ids=tx_ids,
        access_sets=(
            TxAccessSet(
                tx_id=tx_ids[0],
                lane_hint="CONTENT",
                reads=read_set,
                writes=write_set,
                fail_closed_serial=False,
                family="CONTENT",
                barrier_class="SCOPED_PARALLEL",
            ),
        ),
        namespace_prefixes=namespace_prefixes,
    )
    cert = HelperExecutionCertificate(
        chain_id="weall-testnet-candidate",
        block_height=10,
        view=2,
        leader_id="@leader-b593",
        helper_id="@helper-b593",
        validator_epoch=1,
        validator_set_hash="b593-validator-set",
        lane_id=lane.lane_id,
        tx_ids=tx_ids,
        tx_order_hash=make_tx_order_hash(tx_ids),
        receipts_root=hash_receipts(receipts),
        write_set_hash=hash_ordered_strings(write_set),
        read_set_hash=hash_ordered_strings(read_set),
        lane_delta_hash=hash_state_delta_ops([op.to_json() for op in delta_ops]),
        namespace_hash=make_namespace_hash(namespace_prefixes),
        helper_signature="",
        plan_id="b593-production-verifier-boundary",
    )
    return MaterializedLaneResult(
        cert=cert,
        lane_plan=lane,
        namespace_prefixes=namespace_prefixes,
        receipts=receipts,
        read_set=read_set,
        write_set=write_set,
        delta_ops=delta_ops,
    )


def run_harness() -> Json:
    base_state: Json = {"namespaced": {"content:post:1": {"body": "before"}}}
    valid = _materialized_result(value="after")
    valid_status = verify_materialized_lane_result(
        valid,
        expected_lane_plan=valid.lane_plan,
        accepted_certificate=valid.cert,
    )

    tampered_ops = (
        HelperDeltaOp(
            op="set",
            path="namespaced/content:post:1",
            value={"body": "FORGED"},
        ),
    )
    tampered = MaterializedLaneResult(
        cert=valid.cert,
        lane_plan=valid.lane_plan,
        namespace_prefixes=valid.namespace_prefixes,
        receipts=valid.receipts,
        read_set=valid.read_set,
        write_set=valid.write_set,
        delta_ops=tampered_ops,
    )
    tampered_status = verify_materialized_lane_result(
        tampered,
        expected_lane_plan=valid.lane_plan,
        accepted_certificate=valid.cert,
    )
    tampered_merge = merge_materialized_lane_results(
        base_state=base_state,
        lane_results=[tampered],
        lane_plans=(valid.lane_plan,),
        accepted_certificates={valid.cert.lane_id: valid.cert},
    )

    widened_write_set = ("content:post:1", "content:post:2")
    widened_cert = HelperExecutionCertificate(
        **{**valid.cert.to_json(), "write_set_hash": hash_ordered_strings(widened_write_set)}
    )
    widened = MaterializedLaneResult(
        cert=widened_cert,
        lane_plan=valid.lane_plan,
        namespace_prefixes=valid.namespace_prefixes,
        receipts=valid.receipts,
        read_set=valid.read_set,
        write_set=widened_write_set,
        delta_ops=valid.delta_ops,
    )
    widened_status = verify_materialized_lane_result(
        widened,
        expected_lane_plan=valid.lane_plan,
        accepted_certificate=widened_cert,
    )

    duplicate_merge = merge_materialized_lane_results(
        base_state=base_state,
        lane_results=[valid, valid],
        lane_plans=(valid.lane_plan,),
        accepted_certificates={valid.cert.lane_id: valid.cert},
    )

    production_verifier_boundary_ok = bool(
        valid_status.ok
        and not tampered_status.ok
        and tampered_status.code == "lane_delta_hash_mismatch"
        and tampered_merge.accepted_lane_ids == ()
        and tampered_merge.serialized_lane_ids == (valid.cert.lane_id,)
        and tampered_merge.merged_state == base_state
        and not widened_status.ok
        and widened_status.code == "write_set_plan_mismatch"
        and duplicate_merge.accepted_lane_ids == ()
        and duplicate_merge.merged_state == base_state
    )

    return {
        "ok": production_verifier_boundary_ok,
        "batch": "593",
        "mechanism": "helper_materialized_result_production_verifier_boundary_without_activation",
        "production_path_verifier_executed": True,
        "valid_materialized_result_accepted": bool(valid_status.ok),
        "byzantine_helper_output_rejected": not tampered_status.ok,
        "byzantine_rejection_code": tampered_status.code,
        "tampered_lane_serialized": tampered_merge.serialized_lane_ids == (valid.cert.lane_id,),
        "tampered_delta_not_applied": tampered_merge.merged_state == base_state,
        "coordinator_local_write_scope_binding_proven": (
            not widened_status.ok and widened_status.code == "write_set_plan_mismatch"
        ),
        "duplicate_lane_result_rejected": (
            duplicate_merge.accepted_lane_ids == () and duplicate_merge.merged_state == base_state
        ),
        # These stronger properties are deliberately not claimed by this harness.
        # They require a real production helper-vs-serial state execution and restart
        # path, which is not enabled in the current release posture.
        "state_root_equivalence_proven": False,
        "missing_helper_fallback_to_serial_proven": False,
        "restart_replay_root_equal_proven": False,
        "production_block_path_state_root_equivalence_proven": False,
        "mechanism_complete": False,
        "production_helper_execution_enabled": False,
        "public_helper_execution_claimed": False,
        "remaining_required_proof": (
            "independently execute serial and helper-materialized production block paths "
            "from the same canonical input state, compare exact post-state roots, and "
            "repeat through restart/replay before helper activation"
        ),
    }


if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
