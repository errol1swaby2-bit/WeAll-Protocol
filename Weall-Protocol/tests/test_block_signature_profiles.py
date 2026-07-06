from weall.crypto.signature_profiles import PQ_MLDSA_V1

REMOVED_CLASSICAL_PROFILE = "classical-signature-profile-removed"
from weall.runtime.block_admission import admit_bft_block
from weall.runtime.block_signature_profiles import canonical_block_signature_payload, validate_block_signature_profile


def _block(profile=""):
    out = {"chain_id": "weall-testnet-v1", "height": 1, "block_id": "b1", "prev_block_id": "b0", "node_id": "@v", "signature": {"alg": "ML-DSA", "sig": "00", "pubkey": "aa"}}
    if profile:
        out["sig_profile"] = profile
    return out


def test_block_payload_binds_profile_and_chain():
    payload = canonical_block_signature_payload(_block(PQ_MLDSA_V1))
    assert b"weall.block.v1" in payload
    assert b"pq-mldsa-v1" in payload
    assert b"weall-testnet-v1" in payload


def test_strict_block_admission_rejects_missing_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, rej = admit_bft_block(block=_block(""), state={}, bft_enabled=False)
    assert ok is False
    assert rej.reason == "block_signature_profile_missing"


def test_strict_block_admission_rejects_legacy_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, rej = admit_bft_block(block=_block(REMOVED_CLASSICAL_PROFILE), state={}, bft_enabled=False)
    assert ok is False
    assert rej.reason in {"signature_profile_not_allowed", "unknown_signature_profile"}


def test_block_profile_pq_shape_ok_without_requiring_verifier(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    assert validate_block_signature_profile(_block(PQ_MLDSA_V1), require_verifier=False) == (True, "ok")
