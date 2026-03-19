from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.crypto.sig import canonical_tx_message, sign_tx_envelope_dict
from weall.runtime.sigverify import verify_tx_signature


def _seed_hex(priv: Ed25519PrivateKey) -> str:
    return priv.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    ).hex()


def _pub_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw).hex()


def test_prod_requires_chain_id_bound_signature(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ALLOW_LEGACY_SIG_DOMAIN", raising=False)

    priv = Ed25519PrivateKey.generate()
    pub = _pub_hex(priv)
    tx = {
        "tx_type": "POST_CREATE",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"body": "hello"},
        "chain_id": "chain-A",
    }
    signed = sign_tx_envelope_dict(tx=tx, privkey=_seed_hex(priv))
    state = {
        "chain_id": "chain-A",
        "params": {"require_signatures": True},
        "accounts": {"@alice": {"keys": [{"pubkey": pub, "active": True}]}},
    }
    assert verify_tx_signature(state, signed) is True


def test_prod_rejects_legacy_no_chain_id_signature(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ALLOW_LEGACY_SIG_DOMAIN", raising=False)

    priv = Ed25519PrivateKey.generate()
    pub = _pub_hex(priv)
    legacy_tx = {
        "tx_type": "POST_CREATE",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"body": "hello"},
    }
    sig = priv.sign(
        canonical_tx_message(
            tx_type=legacy_tx["tx_type"],
            signer=legacy_tx["signer"],
            nonce=legacy_tx["nonce"],
            payload=legacy_tx["payload"],
        )
    ).hex()
    tx = dict(legacy_tx)
    tx["sig"] = sig
    state = {
        "chain_id": "chain-A",
        "params": {"require_signatures": True},
        "accounts": {"@alice": {"keys": [{"pubkey": pub, "active": True}]}},
    }
    assert verify_tx_signature(state, tx) is False


def test_prod_rejects_chain_id_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ALLOW_LEGACY_SIG_DOMAIN", raising=False)

    priv = Ed25519PrivateKey.generate()
    pub = _pub_hex(priv)
    tx = sign_tx_envelope_dict(
        tx={
            "tx_type": "POST_CREATE",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"body": "hello"},
            "chain_id": "chain-B",
        },
        privkey=_seed_hex(priv),
    )
    state = {
        "chain_id": "chain-A",
        "params": {"require_signatures": True},
        "accounts": {"@alice": {"keys": [{"pubkey": pub, "active": True}]}},
    }
    assert verify_tx_signature(state, tx) is False
