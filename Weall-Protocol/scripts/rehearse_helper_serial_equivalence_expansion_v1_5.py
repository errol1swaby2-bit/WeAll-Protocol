#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from weall.runtime.helper_certificates import HelperExecutionCertificate, hash_receipts, make_namespace_hash, make_tx_order_hash
from weall.runtime.parallel_execution import merge_helper_lane_results, plan_parallel_execution, verify_serial_helper_equivalence


def _tx(tx_id: str, tx_type: str, prefix: str) -> dict[str, Any]:
    return {"tx_id": tx_id, "tx_type": tx_type, "state_prefixes": [prefix], "payload": {"id": tx_id}}


def _serial_executor(txs: list[dict[str, Any]] | tuple[dict[str, Any], ...], _leader_context: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    receipts = [{"tx_id": str(tx.get("tx_id") or ""), "tx_type": str(tx.get("tx_type") or ""), "ok": True, "path": "serial", "effect": str(tx.get("state_prefixes", [""])[0])} for tx in txs]
    return receipts, {"count": len(receipts)}


def _cert_for_lane(lane, receipts: list[dict[str, Any]], *, block_height: int = 88, view: int = 12, validator_epoch: int = 4, validator_set_hash: str = "vh-b561") -> HelperExecutionCertificate:
    return HelperExecutionCertificate(
        chain_id="batch561-helper",
        block_height=block_height,
        view=view,
        leader_id="v-a",
        helper_id=str(lane.helper_id or ""),
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
        lane_id=lane.lane_id,
        tx_ids=lane.tx_ids,
        tx_order_hash=make_tx_order_hash(lane.tx_ids),
        receipts_root=hash_receipts(receipts),
        write_set_hash="write-root",
        read_set_hash="read-root",
        lane_delta_hash="delta-root",
        namespace_hash=make_namespace_hash(lane.namespace_prefixes),
    )


def run_harness() -> dict[str, Any]:
    txs = [
        _tx("t01", "CONTENT_POST_CREATE", "content:post:1"),
        _tx("t02", "CONTENT_REACTION_ADD", "content:reaction:1"),
        _tx("t03", "SOCIAL_FOLLOW", "social:follow:@a:@b"),
        _tx("t04", "POH_ASYNC_REQUEST_OPEN", "identity:poh:@a"),
        _tx("t05", "STORAGE_OFFER_CREATE", "storage:offer:op-a"),
        _tx("t06", "GROUP_JOIN", "group:membership:g1:@a"),
        _tx("t07", "NOTIFICATION_CREATE", "notifications:activity:1"),
        _tx("t08", "REPUTATION_DELTA", "reputation:@a"),
        _tx("t09", "CONTENT_COMMENT_CREATE", "content:comment:1"),
        _tx("t10", "SOCIAL_PROFILE_UPDATE", "social:profile:@a"),
    ]
    validators = ["v-a", "v-b", "v-c", "v-d"]
    plans = plan_parallel_execution(txs=txs, validators=validators, validator_set_hash="vh-b561", view=12, leader_id="v-a")
    context = {"chain_id": "batch561-helper", "block_height": 88, "view": 12, "leader_id": "v-a", "validator_epoch": 4, "validator_set_hash": "vh-b561", "enforce_helper_tx_order_hash": True, "enforce_helper_namespace_hash": True}
    helper_receipts: dict[str, list[dict[str, Any]]] = {}
    helper_certs: dict[str, HelperExecutionCertificate] = {}
    for lane in plans:
        if not lane.helper_id:
            continue
        receipts, _ = _serial_executor(list(lane.txs), context)
        helper_receipts[lane.lane_id] = receipts
        helper_certs[lane.lane_id] = _cert_for_lane(lane, receipts)
    report = verify_serial_helper_equivalence(canonical_txs=txs, lane_plans=plans, helper_certificates=helper_certs, helper_receipts_by_lane=helper_receipts, serial_executor=_serial_executor, leader_context=context)

    # Missing helper certificate must not halt execution: the merge falls back to
    # serial for that lane and preserves canonical tx order.
    missing_certs = dict(helper_certs)
    missing_lane = next((lane.lane_id for lane in plans if lane.helper_id), "")
    if missing_lane:
        missing_certs.pop(missing_lane, None)
    missing_merge = merge_helper_lane_results(canonical_txs=txs, lane_plans=plans, helper_certificates=missing_certs, serial_executor=_serial_executor, leader_context={**context, "helper_receipts": helper_receipts})
    missing_fallbacks = [d.fallback_reason for d in missing_merge.lane_decisions if d.fallback_reason]

    # Byzantine/malformed helper certificate must be rejected deterministically
    # and fall back to serial without changing the final receipt order.
    bad_certs = dict(helper_certs)
    bad_lane = missing_lane
    if bad_lane and bad_lane in bad_certs:
        good = bad_certs[bad_lane]
        bad_certs[bad_lane] = HelperExecutionCertificate(**{**good.to_json(), "tx_order_hash": "bad-order"})
    bad_merge = merge_helper_lane_results(canonical_txs=txs, lane_plans=plans, helper_certificates=bad_certs, serial_executor=_serial_executor, leader_context={**context, "helper_receipts": helper_receipts, "enforce_helper_tx_order_hash": True})
    bad_fallbacks = [d.fallback_reason for d in bad_merge.lane_decisions if d.fallback_reason]
    canonical_ids = [tx["tx_id"] for tx in txs]
    return {
        "ok": bool(report.ok and missing_fallbacks and bad_fallbacks and [r.get("tx_id") for r in missing_merge.receipts] == canonical_ids and [r.get("tx_id") for r in bad_merge.receipts] == canonical_ids),
        "batch": "561",
        "tx_count": len(txs),
        "lane_count": len(plans),
        "helper_lane_count": len([p for p in plans if p.helper_id]),
        "serial_equivalence_ok": report.ok,
        "serial_equivalence_reason": report.reason,
        "missing_helper_fallback_reasons": missing_fallbacks,
        "byzantine_helper_rejection_reasons": bad_fallbacks,
        "missing_helper_preserves_tx_order": [r.get("tx_id") for r in missing_merge.receipts] == canonical_ids,
        "byzantine_helper_preserves_tx_order": [r.get("tx_id") for r in bad_merge.receipts] == canonical_ids,
        "production_helper_execution_enabled": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
