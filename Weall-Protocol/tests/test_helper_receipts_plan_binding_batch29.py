from __future__ import annotations

from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt


def test_helper_receipt_plan_binding_roundtrip_batch29() -> None:
    receipt = sign_helper_receipt(
        chain_id="c1", height=10, validator_epoch=3, validator_set_hash="vh", parent_block_id="p1", lane_id="L1", ordered_tx_ids=("t1",), input_state_hash="in", output_state_hash="out", helper_id="h1", shared_secret="secret", plan_id="plan-1",
    )
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
    ) is True
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
        expected_plan_id="wrong-plan",
    ) is False
