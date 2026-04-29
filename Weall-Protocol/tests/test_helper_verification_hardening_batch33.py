from __future__ import annotations

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash, make_tx_order_hash
from weall.runtime.parallel_execution import LanePlan, merge_helper_lane_results, verify_helper_certificate


def _serial_executor(txs: list[dict]) -> tuple[list[dict], dict]:
    receipts = []
    for tx in txs:
        receipts.append({"tx_id": str(tx.get("tx_id") or ""), "ok": True, "path": "serial"})
    return receipts, {"count": len(receipts)}


def _lane_plan() -> LanePlan:
    tx = {"tx_id": "t1", "tx_type": "CONTENT_POST_CREATE", "state_prefixes": ["content:post:1"]}
    return LanePlan(
        lane_id="CONTENT",
        helper_id="h1",
        txs=(tx,),
        tx_ids=("t1",),
        namespace_prefixes=("content:post:1",),
    )


def test_verify_helper_certificate_strict_rejects_tx_order_hash_mismatch_batch33() -> None:
    lane = _lane_plan()
    cert = HelperExecutionCertificate(
        chain_id="c1",
        block_height=10,
        view=7,
        leader_id="v1",
        helper_id="h1",
        validator_epoch=2,
        validator_set_hash="vh",
        lane_id=lane.lane_id,
        tx_ids=lane.tx_ids,
        tx_order_hash="wrong-order",
        receipts_root="r",
        write_set_hash="w",
        read_set_hash="rd",
        lane_delta_hash="d",
        namespace_hash=make_namespace_hash(lane.namespace_prefixes),
    )
    ok, reason = verify_helper_certificate(
        cert=cert,
        lane_plan=lane,
        expected_helper_id="h1",
        chain_id="c1",
        block_height=10,
        view=7,
        leader_id="v1",
        validator_epoch=2,
        validator_set_hash="vh",
        require_internal_consistency=True,
    )
    assert ok is False
    assert reason == "helper_certificate_inconsistent"


def test_verify_helper_certificate_strict_rejects_namespace_hash_mismatch_batch33() -> None:
    lane = _lane_plan()
    cert = HelperExecutionCertificate(
        chain_id="c1",
        block_height=10,
        view=7,
        leader_id="v1",
        helper_id="h1",
        validator_epoch=2,
        validator_set_hash="vh",
        lane_id=lane.lane_id,
        tx_ids=lane.tx_ids,
        tx_order_hash=make_tx_order_hash(lane.tx_ids),
        receipts_root="r",
        write_set_hash="w",
        read_set_hash="rd",
        lane_delta_hash="d",
        namespace_hash=make_namespace_hash(["identity:user:alice"]),
    )
    ok, reason = verify_helper_certificate(
        cert=cert,
        lane_plan=lane,
        expected_helper_id="h1",
        chain_id="c1",
        block_height=10,
        view=7,
        leader_id="v1",
        validator_epoch=2,
        validator_set_hash="vh",
        require_internal_consistency=True,
    )
    assert ok is False
    assert reason == "namespace_hash_mismatch"


def test_merge_helper_lane_results_strict_consistency_falls_back_on_bad_tx_order_hash_batch33() -> None:
    lane = _lane_plan()
    cert = HelperExecutionCertificate(
        chain_id="c1",
        block_height=10,
        view=7,
        leader_id="v1",
        helper_id="h1",
        validator_epoch=2,
        validator_set_hash="vh",
        lane_id=lane.lane_id,
        tx_ids=lane.tx_ids,
        tx_order_hash="wrong-order",
        receipts_root="r",
        write_set_hash="w",
        read_set_hash="rd",
        lane_delta_hash="d",
        namespace_hash=make_namespace_hash(lane.namespace_prefixes),
    )
    result = merge_helper_lane_results(
        canonical_txs=list(lane.txs),
        lane_plans=(lane,),
        helper_certificates={lane.lane_id: cert},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 10,
            "view": 7,
            "leader_id": "v1",
            "validator_epoch": 2,
            "validator_set_hash": "vh",
            "helper_receipts": {
                lane.lane_id: [{"tx_id": "t1", "ok": True, "path": "helper"}],
            },
            "enforce_helper_certificate_consistency": True,
        },
    )
    assert result.receipts == [{"tx_id": "t1", "ok": True, "path": "serial"}]
    assert result.lane_decisions[0].fallback_reason == "helper_certificate_inconsistent"
