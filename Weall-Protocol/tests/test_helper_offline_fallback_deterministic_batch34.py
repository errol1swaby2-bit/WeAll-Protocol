from __future__ import annotations

from weall.runtime.parallel_execution import merge_helper_lane_results, plan_parallel_execution


def _serial_executor(txs, leader_context=None):
    out = []
    for tx in txs:
        out.append({"tx_id": str(tx["tx_id"]), "result": "ok", "lane": str(tx.get("tx_type", ""))})
    return out


def test_missing_helper_certificate_falls_back_deterministically_batch34() -> None:
    txs = [
        {"tx_id": "a1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:1"]},
        {"tx_id": "a2", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:2"]},
    ]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vh",
        view=9,
        leader_id="v1",
    )
    helper_plans = tuple(plan for plan in lane_plans if plan.helper_id)
    assert helper_plans

    ctx = {
        "chain_id": "c1",
        "block_height": 12,
        "view": 9,
        "leader_id": "v1",
        "validator_epoch": 4,
        "validator_set_hash": "vh",
    }
    first = merge_helper_lane_results(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates={},
        serial_executor=_serial_executor,
        leader_context=ctx,
    )
    second = merge_helper_lane_results(
        canonical_txs=txs,
        lane_plans=lane_plans,
        helper_certificates={},
        serial_executor=_serial_executor,
        leader_context=ctx,
    )

    assert first.receipts == second.receipts
    assert first.lane_decisions == second.lane_decisions
    assert all(not d.used_helper for d in first.lane_decisions)
    assert any(d.fallback_reason == "missing_helper_certificate" for d in first.lane_decisions if d.lane_id != "SERIAL")
