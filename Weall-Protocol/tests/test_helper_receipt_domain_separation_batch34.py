from __future__ import annotations

from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt


def _receipt():
    return sign_helper_receipt(
        chain_id="c1",
        height=10,
        validator_epoch=3,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        ordered_tx_ids=("t1", "t2"),
        input_state_hash="in",
        output_state_hash="out",
        helper_id="h1",
        shared_secret="secret",
        plan_id="plan-1",
    )


def test_helper_receipt_domain_separation_accepts_exact_context_batch34() -> None:
    receipt = _receipt()
    assert verify_helper_receipt(
        receipt,
        shared_secret="secret",
        expected_chain_id="c1",
        expected_height=10,
        expected_validator_epoch=3,
        expected_validator_set_hash="vh",
        expected_parent_block_id="p1",
        expected_lane_id="L1",
        expected_helper_id="h1",
        expected_plan_id="plan-1",
        expected_ordered_tx_ids=("t1", "t2"),
    ) is True


def test_helper_receipt_domain_separation_rejects_context_drift_batch34() -> None:
    receipt = _receipt()
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c2", expected_height=10, expected_validator_epoch=3, expected_validator_set_hash="vh", expected_parent_block_id="p1", expected_lane_id="L1", expected_helper_id="h1", expected_plan_id="plan-1", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=11, expected_validator_epoch=3, expected_validator_set_hash="vh", expected_parent_block_id="p1", expected_lane_id="L1", expected_helper_id="h1", expected_plan_id="plan-1", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=10, expected_validator_epoch=4, expected_validator_set_hash="vh", expected_parent_block_id="p1", expected_lane_id="L1", expected_helper_id="h1", expected_plan_id="plan-1", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=10, expected_validator_epoch=3, expected_validator_set_hash="other", expected_parent_block_id="p1", expected_lane_id="L1", expected_helper_id="h1", expected_plan_id="plan-1", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=10, expected_validator_epoch=3, expected_validator_set_hash="vh", expected_parent_block_id="p2", expected_lane_id="L1", expected_helper_id="h1", expected_plan_id="plan-1", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=10, expected_validator_epoch=3, expected_validator_set_hash="vh", expected_parent_block_id="p1", expected_lane_id="L2", expected_helper_id="h1", expected_plan_id="plan-1", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=10, expected_validator_epoch=3, expected_validator_set_hash="vh", expected_parent_block_id="p1", expected_lane_id="L1", expected_helper_id="h2", expected_plan_id="plan-1", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=10, expected_validator_epoch=3, expected_validator_set_hash="vh", expected_parent_block_id="p1", expected_lane_id="L1", expected_helper_id="h1", expected_plan_id="plan-2", expected_ordered_tx_ids=("t1", "t2")) is False
    assert verify_helper_receipt(receipt, shared_secret="secret", expected_chain_id="c1", expected_height=10, expected_validator_epoch=3, expected_validator_set_hash="vh", expected_parent_block_id="p1", expected_lane_id="L1", expected_helper_id="h1", expected_plan_id="plan-1", expected_ordered_tx_ids=("t2", "t1")) is False
