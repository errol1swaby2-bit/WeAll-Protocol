from weall.crypto.signature_profiles import (
    LEGACY_ED25519_V1,
    PQ_MLKEM_V1,
    PQ_MLDSA_V1,
    PQ_SLHDSA_V1,
    get_signature_profile,
    mode_requires_explicit_sig_profile,
    profile_allowed_for_context,
    signature_profile_registry_json,
)



def test_signature_profile_registry_is_deterministic_and_fail_closed(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    payload = signature_profile_registry_json()
    ids = {p["profile_id"] for p in payload["profiles"]}
    assert {LEGACY_ED25519_V1, PQ_MLDSA_V1, PQ_SLHDSA_V1, PQ_MLKEM_V1}.issubset(ids)
    legacy = get_signature_profile(LEGACY_ED25519_V1)
    assert legacy is not None
    assert legacy.status == "disabled"
    assert legacy.post_quantum is False
    assert get_signature_profile("unknown-profile") is None
    assert mode_requires_explicit_sig_profile() is True
    ok, reason = profile_allowed_for_context("unknown-profile", require_verifier=False)
    assert ok is False
    assert reason == "unknown_signature_profile"


def test_mlkems_are_not_allowed_as_signatures(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = profile_allowed_for_context(PQ_MLKEM_V1, purpose="signing", require_verifier=False)
    assert ok is False
    assert reason == "signature_profile_wrong_purpose"


def test_closed_testnet_default_allows_pq_and_rejects_disabled_legacy_ed25519(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = profile_allowed_for_context(PQ_MLDSA_V1, require_verifier=False)
    assert (ok, reason) == (True, "ok")
    ok, reason = profile_allowed_for_context(LEGACY_ED25519_V1, require_verifier=False)
    assert ok is False
    assert reason == "signature_profile_disabled"


def test_chain_allowlist_cannot_reenable_disabled_legacy_ed25519(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    chain_config = {"crypto": {"allowed_signature_profiles": [LEGACY_ED25519_V1]}}
    ok, reason = profile_allowed_for_context(LEGACY_ED25519_V1, chain_config=chain_config, require_verifier=False)
    assert ok is False
    assert reason == "signature_profile_disabled"
