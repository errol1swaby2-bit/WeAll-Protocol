from weall.crypto.signature_profiles import LEGACY_ED25519_V1, PQ_MLDSA_V1
from weall.runtime.block_signature_profiles import validate_validator_operator_record


def test_validator_operator_record_requires_profile_in_closed_testnet(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = validate_validator_operator_record({"node_pubkey": "aa"}, require_verifier=False)
    assert ok is False
    assert reason == "validator_signature_profile_missing"


def test_validator_operator_record_rejects_legacy_without_allowlist(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = validate_validator_operator_record({"sig_profile": LEGACY_ED25519_V1, "node_pubkey": "aa"}, require_verifier=False)
    assert ok is False
    assert reason in {"signature_profile_not_allowed", "legacy_ed25519_not_allowed"}


def test_validator_operator_record_accepts_pq_shape_without_verifier(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = validate_validator_operator_record({"sig_profile": PQ_MLDSA_V1, "node_pubkey": "aa"}, require_verifier=False)
    assert (ok, reason) == (True, "ok")
