from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash, sign_helper_certificate
from weall.runtime.helper_dispatch import HelperCertificateStore, HelperDispatchContext
from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt
from weall.runtime.parallel_execution import plan_parallel_execution
from weall.testing.sigtools import deterministic_ed25519_keypair


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def _lane_setup():
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    return lane_plans, lane_plan


def _context():
    return HelperDispatchContext(
        chain_id="c1",
        block_height=22,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
    )


def test_helper_store_rejects_missing_helper_pubkey_batch125() -> None:
    lane_plans, lane_plan = _lane_setup()
    seed = (bytes([21]) * 32).hex()
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            helper_id=lane_plan.helper_id,
            validator_epoch=9,
            validator_set_hash="vhash",
            lane_id=lane_plan.lane_id,
            tx_ids=lane_plan.tx_ids,
            tx_order_hash="order",
            receipts_root="receipts",
            write_set_hash="writes",
            read_set_hash="reads",
            lane_delta_hash="delta",
            namespace_hash=make_namespace_hash(["content:post:1"]),
        ),
        privkey=seed,
    )
    store = HelperCertificateStore(context=_context(), lane_plans=lane_plans, helper_pubkeys={})
    status = store.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert status.accepted is False
    assert status.code == "helper_pubkey_missing"


def test_helper_receipt_requires_asymmetric_identity_by_default_batch125() -> None:
    receipt = sign_helper_receipt(
        chain_id="c1",
        height=10,
        validator_epoch=3,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        ordered_tx_ids=("t1",),
        input_state_hash="in",
        output_state_hash="out",
        helper_id="h1",
        shared_secret="secret",
        allow_legacy_shared_secret=True,
        plan_id="plan-1",
    )
    assert verify_helper_receipt(
        receipt,
        expected_chain_id="c1",
        expected_height=10,
        expected_validator_epoch=3,
        expected_validator_set_hash="vh",
        expected_parent_block_id="p1",
        expected_lane_id="L1",
        expected_helper_id="h1",
        expected_plan_id="plan-1",
        expected_ordered_tx_ids=("t1",),
    ) is False


def test_helper_receipt_accepts_pubkey_signature_batch125() -> None:
    pub, priv = deterministic_ed25519_keypair(label="helper-receipt-b125")
    receipt = sign_helper_receipt(
        chain_id="c1",
        height=10,
        validator_epoch=3,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        ordered_tx_ids=("t1",),
        input_state_hash="in",
        output_state_hash="out",
        helper_id="h1",
        privkey=priv,
        plan_id="plan-1",
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
