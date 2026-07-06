import pytest

from weall.api.public_seed_registry import PublicSeedRegistryError, normalize_public_seed_registry
from weall.crypto.signature_profiles import LEGACY_ED25519_V1, PQ_MLDSA_V1


def _registry(profile):
    return {
        "version": 1,
        "network_id": "weall-public-observer-testnet-v1",
        "chain_id": "weall-testnet-v1",
        "genesis_hash": "g",
        "protocol_profile_hash": "p",
        "tx_index_hash": "t",
        "resettable_testnet": True,
        "economics_active": False,
        "seed_api_urls": ["https://api.example.org"],
        "seed_p2p_urls": ["tls://p2p.example.org:30303"],
        "seed_registry_signer": "aa",
        "seed_registry_signature": "bb",
        "seed_registry_sig_profile": profile,
        "validator_endpoints": [],
    }


def test_strict_seed_registry_rejects_legacy_profile(monkeypatch):
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_REQUIRE_SIGNATURES", "1")
    with pytest.raises(PublicSeedRegistryError, match="signature_profile_not_allowed"):
        normalize_public_seed_registry(_registry(LEGACY_ED25519_V1), allow_local=False)


def test_strict_seed_registry_rejects_unknown_profile(monkeypatch):
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_REQUIRE_SIGNATURES", "1")
    with pytest.raises(PublicSeedRegistryError):
        normalize_public_seed_registry(_registry("pq-unknown-v1"), allow_local=False)


def test_seed_registry_declares_pq_profile_before_verification(monkeypatch):
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_REQUIRE_SIGNATURES", "1")
    with pytest.raises(PublicSeedRegistryError, match="bad_signature"):
        normalize_public_seed_registry(_registry(PQ_MLDSA_V1), allow_local=False)
