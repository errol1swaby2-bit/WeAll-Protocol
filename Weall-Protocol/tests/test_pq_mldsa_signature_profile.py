from weall.crypto.pq_mldsa import (
    generate_mldsa65_keypair,
    mldsa_backend_status,
    sign_mldsa65,
    verify_mldsa65_signature,
)


def test_mldsa_backend_status_is_explicit():
    status = mldsa_backend_status()
    assert status["algorithm"] == "ML-DSA-65"
    assert status["backend"] == "pyca-cryptography"
    assert status["available"] in {True, False}


def test_mldsa_sign_verify_if_real_backend_available_otherwise_no_toy_fallback():
    status = mldsa_backend_status()
    if not status["available"]:
        assert verify_mldsa65_signature(message=b"msg", sig="00", pubkey="00") is False
        return

    kp = generate_mldsa65_keypair()
    sig = sign_mldsa65(message=b"weall-pq-test", privkey=kp["privkey"])
    assert verify_mldsa65_signature(message=b"weall-pq-test", sig=sig, pubkey=kp["pubkey"])
    assert not verify_mldsa65_signature(message=b"tampered", sig=sig, pubkey=kp["pubkey"])
