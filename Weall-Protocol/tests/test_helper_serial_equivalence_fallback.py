from __future__ import annotations

from typing import Any, Mapping

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_receipts,
    hash_state_delta_ops,
    make_namespace_hash,
)
from weall.runtime.parallel_execution import (
    LanePlan,
    canonical_lane_plan_fingerprint,
    merge_helper_lane_results,
    plan_parallel_execution,
    verify_serial_helper_equivalence,
)


Json = dict[str, Any]


def _serial_executor(txs: list[dict], _leader_context: dict | None = None) -> tuple[list[dict], dict]:
    receipts = []
    for tx in txs:
        receipts.append(
            {
                "tx_id": str(tx.get("tx_id") or ""),
                "tx_type": str(tx.get("tx_type") or ""),
                "ok": True,
                "path": "serial",
            }
        )
    return receipts, {"count": len(receipts)}


def _tx(tx_id: str, tx_type: str, *, write_key: str) -> Json:
    return {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "write_set": [write_key],
        "state_prefixes": [write_key],
    }


def _lane_receipts(plan: LanePlan) -> list[Json]:
    return [
        {
            "tx_id": str(tx.get("tx_id") or ""),
            "tx_type": str(tx.get("tx_type") or ""),
            "ok": True,
            "path": "serial",
        }
        for tx in plan.txs
    ]


def _lane_delta_ops(plan: LanePlan) -> list[Json]:
    return [{"op": "put", "path": prefix, "value": f"ok:{idx}"} for idx, prefix in enumerate(plan.namespace_prefixes, start=1)]


def _mk_cert(plan: LanePlan, *, block_height: int, view: int, validator_epoch: int, validator_set_hash: str, plan_id: str, delta_hash: str | None = None) -> HelperExecutionCertificate:
    receipts = _lane_receipts(plan)
    delta_ops = _lane_delta_ops(plan)
    return HelperExecutionCertificate(
        chain_id="c1",
        block_height=block_height,
        view=view,
        leader_id="v1",
        helper_id=str(plan.helper_id or ""),
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
        lane_id=plan.lane_id,
        tx_ids=plan.tx_ids,
        tx_order_hash="order",
        receipts_root=hash_receipts(receipts),
        write_set_hash="w",
        read_set_hash="r",
        lane_delta_hash=delta_hash if delta_hash is not None else hash_state_delta_ops(delta_ops),
        namespace_hash=make_namespace_hash(plan.namespace_prefixes),
        plan_id=plan_id,
    )


def test_helper_serial_equivalence_survives_mixed_fallback_paths_batch12() -> None:
    txs = [
        _tx("t1", "CONTENT_CREATE", write_key="content:post:1"),
        _tx("t2", "IDENTITY_UPDATE", write_key="identity:user:alice"),
        _tx("t3", "SOCIAL_FOLLOW", write_key="social:follow:@alice:@bob"),
        _tx("t4", "GROUP_MEMBERSHIP_REQUEST", write_key="group:membership:g1:@alice"),
    ]
    lane_plans = plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh",
        view=22,
        leader_id="v1",
    )
    assert len(lane_plans) == 4
    plan_id = canonical_lane_plan_fingerprint(lane_plans)

    plan_by_tx = {plan.tx_ids[0]: plan for plan in lane_plans}
    content_lane = plan_by_tx["t1"]
    identity_lane = plan_by_tx["t2"]
    social_lane = plan_by_tx["t3"]
    governance_lane = plan_by_tx["t4"]

    helper_certificates = {
        content_lane.lane_id: _mk_cert(content_lane, block_height=45, view=22, validator_epoch=7, validator_set_hash="vh", plan_id=plan_id),
        identity_lane.lane_id: _mk_cert(identity_lane, block_height=45, view=22, validator_epoch=7, validator_set_hash="vh", plan_id=plan_id, delta_hash="bad-delta"),
        governance_lane.lane_id: _mk_cert(governance_lane, block_height=45, view=22, validator_epoch=7, validator_set_hash="vh", plan_id=plan_id),
    }
    helper_receipts: dict[str, list[Mapping[str, Any]]] = {
        content_lane.lane_id: _lane_receipts(content_lane),
        identity_lane.lane_id: _lane_receipts(identity_lane),
        governance_lane.lane_id: [{"tx_id": "wrong", "tx_type": "GROUP_MEMBERSHIP_REQUEST", "ok": True, "path": "serial"}],
    }
    helper_state_deltas: dict[str, list[Mapping[str, Any]]] = {
        content_lane.lane_id: _lane_delta_ops(content_lane),
        identity_lane.lane_id: _lane_delta_ops(identity_lane),
        governance_lane.lane_id: _lane_delta_ops(governance_lane),
    }

    merged = merge_helper_lane_results(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 45,
            "view": 22,
            "leader_id": "v1",
            "validator_epoch": 7,
            "validator_set_hash": "vh",
            "plan_id": plan_id,
            "helper_receipts": helper_receipts,
            "helper_state_deltas": helper_state_deltas,
            "enforce_helper_receipts_root": True,
            "enforce_helper_state_delta_hash": True,
        },
    )
    decisions = {decision.tx_ids[0]: decision for decision in merged.lane_decisions}
    assert decisions["t1"].used_helper is True
    assert decisions["t2"].used_helper is False
    assert decisions["t2"].fallback_reason == "helper_state_delta_hash_mismatch"
    assert decisions["t3"].used_helper is False
    assert decisions["t3"].fallback_reason == "missing_helper_certificate"
    assert decisions["t4"].used_helper is False
    assert decisions["t4"].fallback_reason == "helper_receipts_invalid"

    report = verify_serial_helper_equivalence(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        helper_receipts_by_lane=helper_receipts,
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 45,
            "view": 22,
            "leader_id": "v1",
            "validator_epoch": 7,
            "validator_set_hash": "vh",
            "plan_id": plan_id,
            "helper_state_deltas": helper_state_deltas,
            "enforce_helper_receipts_root": True,
            "enforce_helper_state_delta_hash": True,
        },
    )
    assert report.ok is True
    assert report.reason == "ok"
    assert report.serial_tx_ids == ("t1", "t2", "t3", "t4")
    assert report.helper_tx_ids == ("t1", "t2", "t3", "t4")
