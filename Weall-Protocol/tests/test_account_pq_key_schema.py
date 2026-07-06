from weall.crypto.account_keys import mldsa_account_key_record, validate_account_key_record
from weall.crypto.signature_profiles import PQ_MLDSA_V1

REMOVED_CLASSICAL_PROFILE = "classical-signature-profile-removed"


def test_mldsa_account_key_record_shape():
    rec = mldsa_account_key_record(pubkey="aa" * 32, created_height=123)
    assert rec["sig_profile"] == PQ_MLDSA_V1
    assert rec["pubkeys"]["mldsa"]
    assert rec["created_height"] == 123
    assert rec["revoked_height"] is None
    assert validate_account_key_record(rec, require_verifier=False) == (True, "ok")


def test_ambiguous_key_rejected_in_closed_testnet(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = validate_account_key_record({"pubkey": "aa", "active": True}, require_verifier=False)
    assert ok is False
    assert reason == "account_key_missing_sig_profile"


def test_legacy_key_rejected_without_allowlist_in_closed_testnet(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    rec = {"sig_profile": REMOVED_CLASSICAL_PROFILE, "pubkey": "aa", "active": True}
    ok, reason = validate_account_key_record(rec, require_verifier=False)
    assert ok is False
    assert reason in {"signature_profile_not_allowed", "unknown_signature_profile"}
