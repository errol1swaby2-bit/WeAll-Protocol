from __future__ import annotations

from weall.runtime.helper_certificates import build_plan_misbehavior_proof, sign_helper_certificate


def test_helper_conflicting_certificate_proof_batch33() -> None:
    cert_a = sign_helper_certificate(
        chain_id="c1",
        height=9,
        validator_epoch=2,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        helper_id="h1",
        lane_tx_ids=("t1",),
        descriptor_hash="descriptor-a",
        plan_id="plan-1",
        shared_secret="secret",
        issued_ms=1000,
    )
    cert_b = sign_helper_certificate(
        chain_id="c1",
        height=9,
        validator_epoch=2,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        helper_id="h1",
        lane_tx_ids=("t1",),
        descriptor_hash="descriptor-b",
        plan_id="plan-1",
        shared_secret="secret",
        issued_ms=1001,
    )
    proof = build_plan_misbehavior_proof(certificate_a=cert_a, certificate_b=cert_b)
    assert proof is not None
    assert proof.reason == "conflicting_descriptor_hash_for_same_helper_plan_lane"
    assert proof.helper_id == "h1"
    assert proof.plan_id == "plan-1"
