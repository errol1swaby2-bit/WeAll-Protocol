from weall.crypto.pq_mldsa import generate_mldsa65_keypair
from weall.crypto.sig import canonical_tx_message, sign_mldsa
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.sigverify import verify_tx_signature

REMOVED_CLASSICAL_PROFILE = "classical-signature-profile-removed"


def _pq_keypair():
    kp = generate_mldsa65_keypair()
    return kp["privkey"], kp["pubkey"]


def _state(pubkey, *, sig_profile=PQ_MLDSA_V1, chain_config=None):
    return {
        "chain_id": "weall-testnet-v1",
        "network_id": "weall-public-observer-testnet-v1",
        "params": {"require_signatures": True, "chain_id": "weall-testnet-v1"},
        "chain_config": chain_config or {},
        "accounts": {
            "@alice": {
                "keys": [
                    {"sig_profile": sig_profile, "pubkey": pubkey, "active": True, "created_height": 1, "revoked_height": None}
                ]
            }
        },
    }


def test_closed_testnet_rejects_missing_sig_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    priv, pub = _pq_keypair()
    msg = canonical_tx_message(chain_id="weall-testnet-v1", tx_type="ACCOUNT_UPDATE", signer="@alice", nonce=1, payload={})
    tx = {"chain_id": "weall-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig": sign_mldsa(message=msg, privkey=priv)}
    assert verify_tx_signature(_state(pub), tx) is False


def test_closed_testnet_rejects_unknown_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    _priv, pub = _pq_keypair()
    tx = {"chain_id": "weall-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig_profile": "pq-unknown-v1", "sig": "00"}
    assert verify_tx_signature(_state(pub), tx) is False


def test_closed_testnet_rejects_removed_classical_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    priv, pub = _pq_keypair()
    msg = canonical_tx_message(chain_id="weall-testnet-v1", network_id="weall-public-observer-testnet-v1", sig_profile=REMOVED_CLASSICAL_PROFILE, tx_type="ACCOUNT_UPDATE", signer="@alice", nonce=1, payload={})
    tx = {"chain_id": "weall-testnet-v1", "network_id": "weall-public-observer-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig_profile": REMOVED_CLASSICAL_PROFILE, "sig": sign_mldsa(message=msg, privkey=priv)}
    assert verify_tx_signature(_state(pub), tx) is False


def test_chain_config_cannot_reenable_removed_classical_profile(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    priv, pub = _pq_keypair()
    msg = canonical_tx_message(chain_id="weall-testnet-v1", network_id="weall-public-observer-testnet-v1", sig_profile=REMOVED_CLASSICAL_PROFILE, tx_type="ACCOUNT_UPDATE", signer="@alice", nonce=1, payload={})
    tx = {"chain_id": "weall-testnet-v1", "network_id": "weall-public-observer-testnet-v1", "tx_type": "ACCOUNT_UPDATE", "signer": "@alice", "nonce": 1, "payload": {}, "sig_profile": REMOVED_CLASSICAL_PROFILE, "sig": sign_mldsa(message=msg, privkey=priv)}
    chain_config = {"crypto": {"allowed_signature_profiles": [REMOVED_CLASSICAL_PROFILE]}}
    assert verify_tx_signature(_state(pub, chain_config=chain_config), tx) is False


def test_canonical_tx_message_binds_chain_and_profile():
    a = canonical_tx_message(chain_id="c1", sig_profile=PQ_MLDSA_V1, tx_type="X", signer="@a", nonce=1, payload={})
    b = canonical_tx_message(chain_id="c1", sig_profile=REMOVED_CLASSICAL_PROFILE, tx_type="X", signer="@a", nonce=1, payload={})
    c = canonical_tx_message(chain_id="c2", sig_profile=PQ_MLDSA_V1, tx_type="X", signer="@a", nonce=1, payload={})
    assert a != b
    assert a != c
    assert b"sig_profile" in a and b"chain_id" in a
