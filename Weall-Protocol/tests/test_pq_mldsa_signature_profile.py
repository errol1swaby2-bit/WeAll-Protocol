from weall.crypto.pq_mldsa import (
    MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
    MLDSA_PRIMITIVE_CONTEXT,
    generate_mldsa65_keypair,
    mldsa_backend_status,
    sign_mldsa65,
    verify_mldsa65_signature,
)


def test_mldsa_backend_status_is_real_and_available():
    status = mldsa_backend_status()
    assert status["algorithm"] == "ML-DSA-65"
    assert status["backend"] == "pyca-cryptography"
    assert status["available"] is True
    assert status["repo_locked_cryptography_version"] == "48.0.0"


def test_mldsa_sign_verify_positive_and_negative_paths():
    kp = generate_mldsa65_keypair()
    assert len(bytes.fromhex(kp["pubkey"])) == MLDSA65_PUBLIC_KEY_BYTES
    sig = sign_mldsa65(message=b"weall-pq-test", privkey=kp["privkey"])
    assert len(bytes.fromhex(sig)) == MLDSA65_SIGNATURE_BYTES
    assert verify_mldsa65_signature(message=b"weall-pq-test", sig=sig, pubkey=kp["pubkey"])
    assert not verify_mldsa65_signature(message=b"tampered", sig=sig, pubkey=kp["pubkey"])
    assert not verify_mldsa65_signature(message=b"weall-pq-test", sig="00" + sig[2:], pubkey=kp["pubkey"])


def test_mldsa_profile_uses_one_strict_no_primitive_context_mode():
    kp = generate_mldsa65_keypair()
    msg = b"weall.pq-mldsa-v1.canonical-bytes-only.v1"

    assert MLDSA_PRIMITIVE_CONTEXT is None

    sig = sign_mldsa65(message=msg, privkey=kp["privkey"], context=None)
    assert verify_mldsa65_signature(message=msg, sig=sig, pubkey=kp["pubkey"], context=None)
    assert verify_mldsa65_signature(message=msg, sig=sig, pubkey=kp["pubkey"])

    primitive_context_sig = sign_mldsa65(
        message=msg,
        privkey=kp["privkey"],
        context=b"weall:pq-mldsa-v1:protocol-signature",
    )
    assert not verify_mldsa65_signature(message=msg, sig=primitive_context_sig, pubkey=kp["pubkey"])
