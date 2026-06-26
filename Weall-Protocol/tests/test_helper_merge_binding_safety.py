from __future__ import annotations

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash
from weall.runtime.parallel_execution import LanePlan, merge_helper_lane_results



def _serial_executor(txs, _leader_context):
    return ([{"tx_id": str(tx.get("tx_id") or ""), "path": "serial"} for tx in list(txs or [])], {})



def _helper_cert(*, lane_plan: LanePlan, height: int = 7, view: int = 3) -> HelperExecutionCertificate:
    return HelperExecutionCertificate(
        chain_id="c1",
        block_height=height,
        view=view,
        leader_id="v1",
        helper_id=str(lane_plan.helper_id or ""),
        validator_epoch=2,
        validator_set_hash="vh",
        lane_id=str(lane_plan.lane_id),
        tx_ids=tuple(str(tx_id) for tx_id in lane_plan.tx_ids),
        tx_order_hash="order",
        receipts_root="r",
        write_set_hash="w",
        read_set_hash="rd",
        lane_delta_hash="d",
        namespace_hash=make_namespace_hash(tuple(lane_plan.namespace_prefixes)),
    )



def test_merge_falls_back_when_lane_plan_contract_mismatches_canonical_batch36() -> None:
    tx1 = {"tx_id": "t1", "tx_type": "CONTENT_POST_CREATE"}
    tx2 = {"tx_id": "t2", "tx_type": "IDENTITY_UPDATE"}
    lane_plans = (
        LanePlan(lane_id="L1", helper_id="h1", txs=(tx2,), tx_ids=("t2",), namespace_prefixes=("identity:user:bob",)),
        LanePlan(lane_id="L2", helper_id="h2", txs=(tx1,), tx_ids=("t1",), namespace_prefixes=("content:post:t1",)),
    )

    result = merge_helper_lane_results(
        canonical_txs=[tx1, tx2],
        lane_plans=lane_plans,
        helper_certificates={
            "L1": _helper_cert(lane_plan=lane_plans[0]),
            "L2": _helper_cert(lane_plan=lane_plans[1]),
        },
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 7,
            "view": 3,
            "leader_id": "v1",
            "validator_epoch": 2,
            "validator_set_hash": "vh",
            "helper_receipts": {
                "L1": [{"tx_id": "t2", "path": "helper"}],
                "L2": [{"tx_id": "t1", "path": "helper"}],
            },
        },
    )

    assert [rec["tx_id"] for rec in result.receipts] == ["t1", "t2"]
    assert all(rec["path"] == "serial" for rec in result.receipts)
    assert all(decision.used_helper is False for decision in result.lane_decisions)
    assert all(decision.fallback_reason == "lane_plan_contract_mismatch" for decision in result.lane_decisions)



def test_merge_falls_back_when_lane_plans_duplicate_tx_id_batch36() -> None:
    tx1 = {"tx_id": "t1", "tx_type": "CONTENT_POST_CREATE"}
    lane_plans = (
        LanePlan(lane_id="L1", helper_id="h1", txs=(tx1,), tx_ids=("t1",), namespace_prefixes=("content:post:t1",)),
        LanePlan(lane_id="L2", helper_id="h2", txs=(tx1,), tx_ids=("t1",), namespace_prefixes=("content:post:t1",)),
    )

    result = merge_helper_lane_results(
        canonical_txs=[tx1],
        lane_plans=lane_plans,
        helper_certificates={
            "L1": _helper_cert(lane_plan=lane_plans[0]),
            "L2": _helper_cert(lane_plan=lane_plans[1]),
        },
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 7,
            "view": 3,
            "leader_id": "v1",
            "validator_epoch": 2,
            "validator_set_hash": "vh",
            "helper_receipts": {
                "L1": [{"tx_id": "t1", "path": "helper"}],
                "L2": [{"tx_id": "t1", "path": "helper"}],
            },
        },
    )

    assert result.receipts == [{"tx_id": "t1", "path": "serial"}]
    assert all(decision.used_helper is False for decision in result.lane_decisions)
    assert all(decision.fallback_reason == "lane_plan_duplicate_tx_id" for decision in result.lane_decisions)



def test_merge_falls_back_when_materialized_receipts_do_not_cover_canonical_order_batch36() -> None:
    tx1 = {"tx_id": "t1", "tx_type": "CONTENT_POST_CREATE"}
    tx2 = {"tx_id": "t2", "tx_type": "IDENTITY_UPDATE"}
    lane_plans = (
        LanePlan(lane_id="L1", helper_id="h1", txs=(tx1,), tx_ids=("t1",), namespace_prefixes=("content:post:t1",)),
        LanePlan(lane_id="L2", helper_id="h2", txs=(tx2,), tx_ids=("t2",), namespace_prefixes=("identity:user:bob",)),
    )

    result = merge_helper_lane_results(
        canonical_txs=[tx1, tx2],
        lane_plans=lane_plans,
        helper_certificates={
            "L1": _helper_cert(lane_plan=lane_plans[0]),
            "L2": _helper_cert(lane_plan=lane_plans[1]),
        },
        serial_executor=_serial_executor,
        leader_context={
            "chain_id": "c1",
            "block_height": 7,
            "view": 3,
            "leader_id": "v1",
            "validator_epoch": 2,
            "validator_set_hash": "vh",
            "helper_receipts": {
                "L1": [{"tx_id": "t1", "path": "helper"}],
                "L2": [{"tx_id": "t2", "path": "helper"}],
            },
        },
    )

    assert [rec["tx_id"] for rec in result.receipts] == ["t1", "t2"]
    assert all(decision.used_helper is True for decision in result.lane_decisions)
    assert all(decision.fallback_reason is None for decision in result.lane_decisions)
