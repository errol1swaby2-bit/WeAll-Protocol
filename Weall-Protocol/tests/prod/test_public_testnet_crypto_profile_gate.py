import pytest

from weall.api.public_seed_registry import PublicSeedRegistryError, load_public_seed_registry


def test_checked_in_public_registry_is_blocked_until_pq_resigned(monkeypatch, tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(
        '{"version":1,"network_id":"weall-public-observer-testnet-v1","chain_id":"weall-testnet-v1","genesis_hash":"g","protocol_profile_hash":"p","tx_index_hash":"t","resettable_testnet":true,"economics_active":false,"seed_api_urls":["https://api.example.org"],"seed_p2p_urls":["tls://p2p.example.org:30303"],"seed_registry_signer":"aa","seed_registry_signature":"bb","seed_registry_sig_profile":"legacy-ed25519-v1","validator_endpoints":[]}',
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_REQUIRE_SIGNATURES", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(registry))
    with pytest.raises(PublicSeedRegistryError, match="signature_profile_not_allowed"):
        load_public_seed_registry(allow_local=False)
