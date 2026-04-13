from __future__ import annotations

from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt
from weall.testing.sigtools import deterministic_ed25519_keypair


def test_helper_receipt_binds_plan_id_batch29() -> None:
    pub, priv = deterministic_ed25519_keypair(label="helper-receipt-plan-b29")
    receipt = sign_helper_receipt(
        chain_id="c1", height=10, validator_epoch=3, validator_set_hash="vh", parent_block_id="p1", lane_id="L1", ordered_tx_ids=("t1",), input_state_hash="in", output_state_hash="out", helper_id="h1", privkey=priv, plan_id="plan-1",
    )
    assert verify_helper_receipt(
        receipt,
        helper_pubkey=pub,
        expected_chain_id="c1",
        expected_height=10,
        expected_validator_epoch=3,
        expected_validator_set_hash="vh",
        expected_parent_block_id="p1",
        expected_lane_id="L1",
        expected_helper_id="h1",
        expected_plan_id="plan-1",
        expected_ordered_tx_ids=("t1",),
    ) is True


def test_helper_receipt_rejects_plan_id_mismatch_batch29() -> None:
    pub, priv = deterministic_ed25519_keypair(label="helper-receipt-plan-b29-mismatch")
    receipt = sign_helper_receipt(
        chain_id="c1", height=10, validator_epoch=3, validator_set_hash="vh", parent_block_id="p1", lane_id="L1", ordered_tx_ids=("t1",), input_state_hash="in", output_state_hash="out", helper_id="h1", privkey=priv, plan_id="plan-1",
    )
    assert verify_helper_receipt(
        receipt,
        helper_pubkey=pub,
        expected_chain_id="c1",
        expected_height=10,
        expected_validator_epoch=3,
        expected_validator_set_hash="vh",
        expected_parent_block_id="p1",
        expected_lane_id="L1",
        expected_helper_id="h1",
        expected_plan_id="plan-2",
        expected_ordered_tx_ids=("t1",),
    ) is False
