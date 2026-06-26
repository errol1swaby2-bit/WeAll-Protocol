from __future__ import annotations

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash


def _mk_cert(*, tx_order_hash: str) -> HelperExecutionCertificate:
    return HelperExecutionCertificate(
        chain_id="c1",
        block_height=9,
        view=5,
        leader_id="v1",
        helper_id="v2",
        validator_epoch=3,
        validator_set_hash="vh",
        lane_id="PARALLEL_CONTENT",
        tx_ids=("t1", "t2"),
        tx_order_hash=tx_order_hash,
        receipts_root="receipts",
        write_set_hash="writes",
        read_set_hash="reads",
        lane_delta_hash="delta",
        namespace_hash=make_namespace_hash(["content:post:1"]),
    )


def test_helper_execution_certificate_internal_consistency_accepts_matching_tx_order_hash_batch1() -> None:
    cert = _mk_cert(tx_order_hash="")
    repaired = HelperExecutionCertificate(**{**cert.to_json(), "tx_order_hash": cert.compute_tx_order_hash()})
    assert repaired.verify_internal_consistency() is True


def test_helper_execution_certificate_internal_consistency_rejects_mismatched_tx_order_hash_batch1() -> None:
    cert = _mk_cert(tx_order_hash="wrong")
    assert cert.verify_internal_consistency() is False
