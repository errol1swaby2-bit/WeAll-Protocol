from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.crypto.sig import canonical_tx_message, sign_ed25519
from weall.crypto.signature_profiles import LEGACY_ED25519_V1, PQ_MLDSA_V1
from weall.runtime.sigverify import verify_tx_signature


def _ed_keypair():
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def _state(pubkey, *, chain_config=None):
    return {
        "chain_id": "weall-testnet-v1",
        "network_id": "weall-public-observer-testnet-v1",
        "params": {"require_signatures": True, "chain_id": "weall-testnet-v1"},
        "chain_config": chain_config or {},
        "accounts": {
            "@alice": {
                "keys": [
                    {"sig_profile": LEGACY_ED25519_V1, "pubkey": pubkey, "active": True, "created_height": 1, "revoked_height": None}
                ]
            }
        },
    }


def test_closed_testnet_rejects_missing_sig_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    priv, pub = _ed_keypair()
    msg = canonical_tx_message(chain_id="weall-testnet-v1", tx_type="ACCOUNT_UPDATE", signer="@alice", nonce=1, payload={})
    tx = {"chain_id": "weall-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig": sign_ed25519(message=msg, privkey=priv)}
    assert verify_tx_signature(_state(pub), tx) is False


def test_closed_testnet_rejects_unknown_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    _priv, pub = _ed_keypair()
    tx = {"chain_id": "weall-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig_profile": "pq-unknown-v1", "sig": "00"}
    assert verify_tx_signature(_state(pub), tx) is False


def test_closed_testnet_rejects_legacy_without_explicit_chain_allowlist(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    priv, pub = _ed_keypair()
    msg = canonical_tx_message(chain_id="weall-testnet-v1", network_id="weall-public-observer-testnet-v1", sig_profile=LEGACY_ED25519_V1, tx_type="ACCOUNT_UPDATE", signer="@alice", nonce=1, payload={})
    tx = {"chain_id": "weall-testnet-v1", "network_id": "weall-public-observer-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig_profile": LEGACY_ED25519_V1, "sig": sign_ed25519(message=msg, privkey=priv)}
    assert verify_tx_signature(_state(pub), tx) is False


def test_legacy_migration_tx_can_pass_only_when_chain_config_allows(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    priv, pub = _ed_keypair()
    msg = canonical_tx_message(chain_id="weall-testnet-v1", network_id="weall-public-observer-testnet-v1", sig_profile=LEGACY_ED25519_V1, tx_type="ACCOUNT_UPDATE", signer="@alice", nonce=1, payload={})
    tx = {"chain_id": "weall-testnet-v1", "network_id": "weall-public-observer-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig_profile": LEGACY_ED25519_V1, "sig": sign_ed25519(message=msg, privkey=priv)}
    chain_config = {"crypto": {"allowed_signature_profiles": [LEGACY_ED25519_V1], "allow_legacy_ed25519": True}}
    assert verify_tx_signature(_state(pub, chain_config=chain_config), tx) is True


def test_canonical_tx_message_binds_chain_and_profile():
    a = canonical_tx_message(chain_id="c1", sig_profile=PQ_MLDSA_V1, tx_type="X", signer="@a", nonce=1, payload={})
    b = canonical_tx_message(chain_id="c1", sig_profile=LEGACY_ED25519_V1, tx_type="X", signer="@a", nonce=1, payload={})
    c = canonical_tx_message(chain_id="c2", sig_profile=PQ_MLDSA_V1, tx_type="X", signer="@a", nonce=1, payload={})
    assert a != b
    assert a != c
    assert b"sig_profile" in a and b"chain_id" in a
