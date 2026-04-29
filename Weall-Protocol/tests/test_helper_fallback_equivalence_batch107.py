from __future__ import annotations

from typing import Any

from weall.runtime.helper_certificates import HelperExecutionCertificate, hash_receipts, make_namespace_hash, make_tx_order_hash
from weall.runtime.parallel_execution import (
    LanePlan,
    canonical_lane_plan_fingerprint,
    merge_helper_lane_results,
    verify_serial_helper_equivalence,
)

Json = dict[str, Any]


def _serial_executor(txs, _leader_context=None):
    return (
        [
            {
                "tx_id": str(tx.get("tx_id") or ""),
                "tx_type": str(tx.get("tx_type") or ""),
                "ok": True,
                "path": "serial",
            }
            for tx in list(txs or [])
        ],
        {},
    )


def _lane(tx_id: str, tx_type: str, lane_id: str, helper_id: str, namespace: str) -> LanePlan:
    tx = {"tx_id": tx_id, "tx_type": tx_type, "state_prefixes": [namespace]}
    return LanePlan(
        lane_id=lane_id,
        helper_id=helper_id,
        txs=(tx,),
        tx_ids=(tx_id,),
        namespace_prefixes=(namespace,),
    )


def _lane_receipts(plan: LanePlan) -> list[Json]:
    tx = plan.txs[0]
    return [{"tx_id": plan.tx_ids[0], "tx_type": str(tx.get("tx_type") or ""), "ok": True, "path": "serial"}]


def _cert(plan: LanePlan, *, plan_id: str, manifest_hash: str, tx_order_hash: str | None = None, namespace_hash: str | None = None) -> HelperExecutionCertificate:
    return HelperExecutionCertificate(
        chain_id="c1",
        block_height=45,
        view=12,
        leader_id="v1",
        helper_id=str(plan.helper_id or ""),
        validator_epoch=4,
        validator_set_hash="vh",
        lane_id=plan.lane_id,
        tx_ids=plan.tx_ids,
        tx_order_hash=tx_order_hash if tx_order_hash is not None else make_tx_order_hash(plan.tx_ids),
        receipts_root=hash_receipts(_lane_receipts(plan)),
        write_set_hash="w",
        read_set_hash="r",
        lane_delta_hash="d",
        namespace_hash=namespace_hash if namespace_hash is not None else make_namespace_hash(plan.namespace_prefixes),
        plan_id=plan_id,
        manifest_hash=manifest_hash,
    )


def test_mixed_helper_strict_binding_fallbacks_preserve_serial_equivalence_batch107() -> None:
    lane_a = _lane("t1", "CONTENT_POST_CREATE", "L1", "h1", "content:post:t1")
    lane_b = _lane("t2", "IDENTITY_UPDATE", "L2", "h2", "identity:user:alice")
    lane_c = _lane("t3", "SOCIAL_FOLLOW", "L3", "h3", "social:follow:@alice:@bob")
    lane_plans = (lane_a, lane_b, lane_c)
    canonical_txs = [dict(lane.txs[0]) for lane in lane_plans]
    plan_id = canonical_lane_plan_fingerprint(lane_plans)

    helper_certificates = {
        lane_a.lane_id: _cert(lane_a, plan_id=plan_id, manifest_hash="manifest-1"),
        lane_b.lane_id: _cert(lane_b, plan_id="", manifest_hash="manifest-1"),
        lane_c.lane_id: _cert(lane_c, plan_id=plan_id, manifest_hash="manifest-1", tx_order_hash="wrong-order"),
    }
    helper_receipts = {
        lane_a.lane_id: _lane_receipts(lane_a),
        lane_b.lane_id: _lane_receipts(lane_b),
        lane_c.lane_id: _lane_receipts(lane_c),
    }

    ctx = {
        "chain_id": "c1",
        "block_height": 45,
        "view": 12,
        "leader_id": "v1",
        "validator_epoch": 4,
        "validator_set_hash": "vh",
        "plan_id": plan_id,
        "manifest_hash": "manifest-1",
        "helper_receipts": helper_receipts,
        "enforce_helper_plan_id_match": True,
        "enforce_helper_manifest_hash_match": True,
        "enforce_helper_tx_order_hash": True,
    }

    first = merge_helper_lane_results(
        canonical_txs=canonical_txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        serial_executor=_serial_executor,
        leader_context=ctx,
    )
    second = merge_helper_lane_results(
        canonical_txs=canonical_txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        serial_executor=_serial_executor,
        leader_context=ctx,
    )

    assert first.receipts == second.receipts
    assert first.lane_decisions == second.lane_decisions
    decisions = {decision.tx_ids[0]: decision for decision in first.lane_decisions}
    assert decisions["t1"].used_helper is True
    assert decisions["t2"].used_helper is False
    assert decisions["t2"].fallback_reason == "plan_id_mismatch"
    assert decisions["t3"].used_helper is False
    assert decisions["t3"].fallback_reason == "tx_order_hash_mismatch"

    report = verify_serial_helper_equivalence(
        canonical_txs=canonical_txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        helper_receipts_by_lane=helper_receipts,
        serial_executor=_serial_executor,
        leader_context=ctx,
    )
    assert report.ok is True
    assert report.reason == "ok"
    assert report.serial_tx_ids == ("t1", "t2", "t3")
    assert report.helper_tx_ids == ("t1", "t2", "t3")
