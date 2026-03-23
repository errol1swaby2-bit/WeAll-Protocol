from __future__ import annotations

from weall.runtime.helper_certificates import HelperExecutionCertificate, hash_receipts, make_namespace_hash
from weall.runtime.parallel_execution import plan_parallel_execution, verify_serial_helper_equivalence


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


def _tx(tx_id: str, tx_type: str, prefix: str) -> dict:
    return {"tx_id": tx_id, "tx_type": tx_type, "state_prefixes": [prefix]}


def _helper_cert_and_receipts(lane, *, block_height: int, view: int, validator_epoch: int, validator_set_hash: str):
    receipts = [
        {"tx_id": tx["tx_id"], "tx_type": tx["tx_type"], "ok": True, "path": "serial"}
        for tx in lane.txs
    ]
    cert = HelperExecutionCertificate(
        chain_id="c1",
        block_height=block_height,
        view=view,
        leader_id="v1",
        helper_id=lane.helper_id,
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
        lane_id=lane.lane_id,
        tx_ids=lane.tx_ids,
        tx_order_hash="order",
        receipts_root=hash_receipts(receipts),
        write_set_hash="w",
        read_set_hash="r",
        lane_delta_hash="d",
        namespace_hash=make_namespace_hash(lane.namespace_prefixes),
    )
    return cert, receipts


def test_helper_merge_matches_serial_executor_for_disjoint_lanes_batch34() -> None:
    txs = [
        _tx("t1", "CONTENT_CREATE", "content:post:1"),
        _tx("t2", "IDENTITY_UPDATE", "identity:user:alice"),
        _tx("t3", "SOCIAL_FOLLOW", "social:follow:@alice:@bob"),
    ]
    lane_plans = plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh",
        view=9,
        leader_id="v1",
    )
    helper_certificates = {}
    helper_receipts = {}
    for lane in lane_plans:
        if not lane.helper_id:
            continue
        cert, receipts = _helper_cert_and_receipts(
            lane, block_height=14, view=9, validator_epoch=3, validator_set_hash="vh"
        )
        helper_certificates[lane.lane_id] = cert
        helper_receipts[lane.lane_id] = receipts
    report = verify_serial_helper_equivalence(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        helper_receipts_by_lane=helper_receipts,
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 14,
            "view": 9,
            "leader_id": "v1",
            "validator_epoch": 3,
            "validator_set_hash": "vh",
        },
    )
    assert report.ok is True
    assert report.reason == "ok"
    assert report.serial_tx_ids == ("t1", "t2", "t3")


def test_helper_merge_reports_receipt_mismatch_batch34() -> None:
    txs = [_tx("t1", "CONTENT_CREATE", "content:post:1")]
    lane_plans = plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3"],
        validator_set_hash="vh",
        view=10,
        leader_id="v1",
    )
    lane = next(plan for plan in lane_plans if plan.helper_id)
    cert, _receipts = _helper_cert_and_receipts(
        lane, block_height=15, view=10, validator_epoch=4, validator_set_hash="vh"
    )
    report = verify_serial_helper_equivalence(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates={lane.lane_id: cert},
        helper_receipts_by_lane={lane.lane_id: [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "ok": False, "path": "serial"}]},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 15,
            "view": 10,
            "leader_id": "v1",
            "validator_epoch": 4,
            "validator_set_hash": "vh",
        },
    )
    assert report.ok is False
    assert report.reason == "receipt_mismatch"
