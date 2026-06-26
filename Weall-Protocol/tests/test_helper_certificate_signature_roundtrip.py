from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
    verify_helper_certificate_signature,
)





def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()



def test_helper_certificate_signature_roundtrip_batch2() -> None:
    priv = (bytes([7]) * 32).hex()
    pub = _pub_hex_from_seed(priv)
    cert = HelperExecutionCertificate(
        chain_id="c1",
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
    )
    signed = sign_helper_certificate(cert, privkey=priv)
    assert verify_helper_certificate_signature(signed, helper_pubkey=pub) is True
