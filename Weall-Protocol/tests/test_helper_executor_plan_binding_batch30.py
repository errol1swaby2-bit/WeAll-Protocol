from __future__ import annotations

from weall.runtime.helper_executor import HelperExecutor


def test_helper_executor_carries_plan_id_into_receipt_batch30() -> None:
    executor = HelperExecutor({"h1": "secret"})
    result = executor.execute_lane(
        chain_id="c1",
        height=10,
        parent_block_id="p1",
        validator_epoch=3,
        validator_set_hash="vh",
        lane_id="L1",
        helper_id="h1",
        state={"balances": {}, "nonces": {}},
        lane_txs=({"tx_id": "t1", "signer": "alice", "nonce": 1, "delta": 5, "received_ms": 1},),
        plan_id="plan-1",
    )
    assert result.plan_id == "plan-1"
    assert result.receipt.plan_id == "plan-1"
    assert executor.verify_lane_result(
        result,
        chain_id="c1",
        height=10,
        validator_epoch=3,
        validator_set_hash="vh",
        parent_block_id="p1",
        expected_plan_id="plan-1",
    ) is True
    assert executor.verify_lane_result(
        result,
        chain_id="c1",
        height=10,
        validator_epoch=3,
        validator_set_hash="vh",
        parent_block_id="p1",
        expected_plan_id="wrong-plan",
    ) is False
