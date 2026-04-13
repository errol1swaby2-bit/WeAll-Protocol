from __future__ import annotations

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash, make_tx_order_hash
from weall.runtime.parallel_execution import LanePlan, merge_helper_lane_results, verify_helper_certificate


def _serial_executor(txs, _leader_context=None):
    return ([{"tx_id": str(tx.get("tx_id") or ""), "path": "serial"} for tx in list(txs or [])], {})


def _lane_plan() -> LanePlan:
    tx = {"tx_id": "t1", "tx_type": "CONTENT_POST_CREATE", "state_prefixes": ["content:post:t1"]}
    return LanePlan(
        lane_id="L1",
        helper_id="h1",
        txs=(tx,),
        tx_ids=("t1",),
        namespace_prefixes=("content:post:t1",),
    )


def _base_cert(plan: LanePlan, **overrides) -> HelperExecutionCertificate:
    payload = {
        "chain_id": "c1",
        "block_height": 22,
        "view": 7,
        "leader_id": "v1",
        "helper_id": "h1",
        "validator_epoch": 9,
        "validator_set_hash": "vhash",
        "lane_id": plan.lane_id,
        "tx_ids": plan.tx_ids,
        "tx_order_hash": make_tx_order_hash(plan.tx_ids),
        "receipts_root": "r",
        "write_set_hash": "w",
        "read_set_hash": "rd",
        "lane_delta_hash": "d",
        "namespace_hash": make_namespace_hash(plan.namespace_prefixes),
        "plan_id": "plan-1",
        "manifest_hash": "manifest-1",
    }
    payload.update(overrides)
    return HelperExecutionCertificate(**payload)


def test_verify_helper_certificate_rejects_missing_plan_id_when_strictly_required_batch107() -> None:
    lane = _lane_plan()
    cert = _base_cert(lane, plan_id="")
    ok, reason = verify_helper_certificate(
        cert=cert,
        lane_plan=lane,
        expected_helper_id="h1",
        chain_id="c1",
        block_height=22,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
        plan_id="plan-1",
        require_plan_id_match=True,
    )
    assert ok is False
    assert reason == "plan_id_mismatch"


def test_verify_helper_certificate_rejects_missing_manifest_hash_when_strictly_required_batch107() -> None:
    lane = _lane_plan()
    cert = _base_cert(lane, manifest_hash="")
    ok, reason = verify_helper_certificate(
        cert=cert,
        lane_plan=lane,
        expected_helper_id="h1",
        chain_id="c1",
        block_height=22,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
        manifest_hash="manifest-1",
        require_manifest_hash_match=True,
    )
    assert ok is False
    assert reason == "manifest_hash_mismatch"


def test_verify_helper_certificate_can_enforce_tx_order_hash_without_full_internal_consistency_batch107() -> None:
    lane = _lane_plan()
    cert = _base_cert(lane, tx_order_hash="wrong-order")
    ok, reason = verify_helper_certificate(
        cert=cert,
        lane_plan=lane,
        expected_helper_id="h1",
        chain_id="c1",
        block_height=22,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
        enforce_tx_order_hash=True,
    )
    assert ok is False
    assert reason == "tx_order_hash_mismatch"


def test_merge_helper_lane_results_falls_back_on_missing_plan_binding_when_required_batch107() -> None:
    lane = _lane_plan()
    cert = _base_cert(lane, plan_id="")
    merged = merge_helper_lane_results(
        canonical_txs=list(lane.txs),
        lane_plans=(lane,),
        helper_certificates={lane.lane_id: cert},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 22,
            "view": 7,
            "leader_id": "v1",
            "validator_epoch": 9,
            "validator_set_hash": "vhash",
            "plan_id": "plan-1",
            "helper_receipts": {lane.lane_id: [{"tx_id": "t1", "path": "helper"}]},
            "enforce_helper_plan_id_match": True,
        },
    )
    assert merged.receipts == [{"tx_id": "t1", "path": "serial"}]
    assert merged.lane_decisions[0].used_helper is False
    assert merged.lane_decisions[0].fallback_reason == "plan_id_mismatch"


def test_merge_helper_lane_results_falls_back_on_missing_manifest_binding_when_required_batch107() -> None:
    lane = _lane_plan()
    cert = _base_cert(lane, manifest_hash="")
    merged = merge_helper_lane_results(
        canonical_txs=list(lane.txs),
        lane_plans=(lane,),
        helper_certificates={lane.lane_id: cert},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 22,
            "view": 7,
            "leader_id": "v1",
            "validator_epoch": 9,
            "validator_set_hash": "vhash",
            "manifest_hash": "manifest-1",
            "helper_receipts": {lane.lane_id: [{"tx_id": "t1", "path": "helper"}]},
            "enforce_helper_manifest_hash_match": True,
        },
    )
    assert merged.receipts == [{"tx_id": "t1", "path": "serial"}]
    assert merged.lane_decisions[0].used_helper is False
    assert merged.lane_decisions[0].fallback_reason == "manifest_hash_mismatch"
