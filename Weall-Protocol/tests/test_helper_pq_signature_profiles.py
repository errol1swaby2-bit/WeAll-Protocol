from __future__ import annotations

from weall.crypto.pq_mldsa import generate_mldsa65_keypair
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
    verify_helper_certificate_signature,
)
from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt


def test_helper_receipt_supports_pq_mldsa_profile():
    kp = generate_mldsa65_keypair()
    receipt = sign_helper_receipt(
        chain_id="weall-testnet-v1",
        height=7,
        validator_epoch=1,
        validator_set_hash="set-hash",
        parent_block_id="parent",
        lane_id="PARALLEL_CONTENT",
        ordered_tx_ids=("tx1", "tx2"),
        input_state_hash="in",
        output_state_hash="out",
        helper_id="helper-a",
        plan_id="plan-pq",
        privkey=kp["privkey"],
        sig_profile="pq-mldsa-v1",
    )
    assert receipt.sig_profile == "pq-mldsa-v1"
    assert verify_helper_receipt(
        receipt,
        helper_pubkey=kp["pubkey"],
        expected_chain_id="weall-testnet-v1",
        expected_height=7,
        expected_validator_epoch=1,
        expected_validator_set_hash="set-hash",
        expected_parent_block_id="parent",
        expected_lane_id="PARALLEL_CONTENT",
        expected_helper_id="helper-a",
        expected_plan_id="plan-pq",
        expected_ordered_tx_ids=("tx1", "tx2"),
    ) is True
    assert verify_helper_receipt(
        receipt,
        helper_pubkey=kp["pubkey"],
        expected_chain_id="other-chain",
        expected_height=7,
        expected_validator_epoch=1,
        expected_validator_set_hash="set-hash",
        expected_parent_block_id="parent",
        expected_lane_id="PARALLEL_CONTENT",
        expected_helper_id="helper-a",
        expected_plan_id="plan-pq",
        expected_ordered_tx_ids=("tx1", "tx2"),
    ) is False


def test_helper_certificate_supports_pq_mldsa_profile():
    kp = generate_mldsa65_keypair()
    cert = HelperExecutionCertificate(
        chain_id="weall-testnet-v1",
        block_height=9,
        view=5,
        leader_id="v1",
        helper_id="v2",
        validator_epoch=3,
        validator_set_hash="vh",
        lane_id="PARALLEL_CONTENT",
        tx_ids=("t1", "t2"),
        tx_order_hash="order",
        receipts_root="receipts",
        write_set_hash="writes",
        read_set_hash="reads",
        lane_delta_hash="delta",
        namespace_hash=make_namespace_hash(["content:post:1"]),
        sig_profile="pq-mldsa-v1",
    )
    signed = sign_helper_certificate(cert, privkey=kp["privkey"], sig_profile="pq-mldsa-v1")
    assert signed.sig_profile == "pq-mldsa-v1"
    assert verify_helper_certificate_signature(signed, helper_pubkey=kp["pubkey"]) is True
    tampered = HelperExecutionCertificate(**{**signed.to_json(), "lane_delta_hash": "tampered"})
    assert verify_helper_certificate_signature(tampered, helper_pubkey=kp["pubkey"]) is False
