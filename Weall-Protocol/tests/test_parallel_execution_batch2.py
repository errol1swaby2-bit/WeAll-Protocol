from __future__ import annotations

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash
from weall.runtime.parallel_execution import merge_helper_lane_results, plan_parallel_execution



def _serial_executor(txs: list[dict]) -> tuple[list[dict], dict]:
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



def _make_tx(tx_id: str, tx_type: str, prefix: str) -> dict:
    return {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "state_prefixes": [prefix],
    }



def test_missing_helper_certificate_falls_back_to_serial_and_preserves_order_batch2() -> None:
    txs = [
        _make_tx("t1", "CONTENT_CREATE", "content:post:1"),
        _make_tx("t2", "IDENTITY_UPDATE", "identity:user:alice"),
    ]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh",
        view=7,
        leader_id="v1",
    )
    result = merge_helper_lane_results(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates={},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 10,
            "view": 7,
            "leader_id": "v1",
            "validator_epoch": 2,
            "validator_set_hash": "vh",
            "helper_receipts": {},
        },
    )
    assert [rec["tx_id"] for rec in result.receipts] == ["t1", "t2"]
    assert all(rec["path"] == "serial" for rec in result.receipts)



def test_invalid_namespace_certificate_is_rejected_and_serialized_batch2() -> None:
    txs = [_make_tx("t1", "CONTENT_CREATE", "content:post:1")]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh",
        view=8,
        leader_id="v1",
    )
    lane = next(plan for plan in lane_plans if plan.lane_id != "SERIAL")
    cert = HelperExecutionCertificate(
        chain_id="c1",
        block_height=11,
        view=8,
        leader_id="v1",
        helper_id=lane.helper_id,
        validator_epoch=2,
        validator_set_hash="vh",
        lane_id=lane.lane_id,
        tx_ids=lane.tx_ids,
        tx_order_hash="ignored",
        receipts_root="r",
        write_set_hash="w",
        read_set_hash="rd",
        lane_delta_hash="d",
        namespace_hash=make_namespace_hash(["identity:user:alice"]),
    )
    result = merge_helper_lane_results(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates={lane.lane_id: cert},
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 11,
            "view": 8,
            "leader_id": "v1",
            "validator_epoch": 2,
            "validator_set_hash": "vh",
            "helper_receipts": {
                lane.lane_id: [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "ok": True, "path": "helper"}]
            },
        },
    )
    assert result.receipts[0]["path"] == "serial"
    assert any(decision.fallback_reason == "namespace_scope_invalid" for decision in result.lane_decisions)



def test_helper_receipts_merge_deterministically_when_valid_batch2() -> None:
    txs = [
        _make_tx("t1", "CONTENT_CREATE", "content:post:1"),
        _make_tx("t2", "IDENTITY_UPDATE", "identity:user:alice"),
    ]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh",
        view=12,
        leader_id="v1",
    )
    helper_certs = {}
    helper_receipts = {}
    for lane in lane_plans:
        if lane.lane_id == "SERIAL" or not lane.helper_id:
            continue
        helper_certs[lane.lane_id] = HelperExecutionCertificate(
            chain_id="c1",
            block_height=13,
            view=12,
            leader_id="v1",
            helper_id=lane.helper_id,
            validator_epoch=4,
            validator_set_hash="vh",
            lane_id=lane.lane_id,
            tx_ids=lane.tx_ids,
            tx_order_hash="order",
            receipts_root="r",
            write_set_hash="w",
            read_set_hash="rd",
            lane_delta_hash="d",
            namespace_hash=make_namespace_hash(
                [prefix for tx in lane.txs for prefix in tx.get("state_prefixes", [])]
            ),
        )
        helper_receipts[lane.lane_id] = [
            {"tx_id": tx["tx_id"], "tx_type": tx["tx_type"], "ok": True, "path": "helper"}
            for tx in lane.txs
        ]
    result = merge_helper_lane_results(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certs,
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 13,
            "view": 12,
            "leader_id": "v1",
            "validator_epoch": 4,
            "validator_set_hash": "vh",
            "helper_receipts": helper_receipts,
        },
    )
    assert [rec["tx_id"] for rec in result.receipts] == ["t1", "t2"]
    assert all(rec["path"] == "helper" for rec in result.receipts)
