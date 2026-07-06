from __future__ import annotations

import hashlib
from typing import Any

from weall.crypto.pq_mldsa import mldsa65_public_key_from_seed
from weall.crypto.sig import canonical_tx_message, sign_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1

Json = dict[str, Any]


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def deterministic_mldsa_keypair(*, label: str) -> tuple[str, str]:
    """Deterministically derive a test-only ML-DSA-65 seed and public key."""
    seed_hex = _sha256(("weall-test-pq-mldsa:" + (label or "")).encode("utf-8")).hex()
    pk_hex = mldsa65_public_key_from_seed(privkey=seed_hex, encoding="hex")
    return pk_hex, seed_hex


def ensure_account_has_test_key(accounts: Json, *, account_id: str) -> str:
    if not isinstance(accounts, dict):
        raise TypeError("accounts must be a dict")
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        acct = {}
        accounts[account_id] = acct
    keys = acct.get("keys")
    if not isinstance(keys, list):
        keys = []
        acct["keys"] = keys
    for rec in keys:
        if isinstance(rec, dict) and rec.get("active", True):
            pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), dict) else {}
            pk = pubkeys.get("mldsa") or rec.get("pubkey")
            if isinstance(pk, str) and pk.strip():
                return pk.strip()
    pubkey_hex, _ = deterministic_mldsa_keypair(label=account_id)
    keys.append({"sig_profile": PQ_MLDSA_V1, "pubkeys": {"mldsa": pubkey_hex}, "active": True})
    return pubkey_hex


def sign_tx_dict(tx: Json, *, label: str | None = None) -> Json:
    if not isinstance(tx, dict):
        raise TypeError("tx must be a dict")
    tx_type = str(tx.get("tx_type") or "").strip()
    signer = str(tx.get("signer") or "").strip()
    nonce = int(tx.get("nonce") or 0)
    payload = tx.get("payload") if isinstance(tx.get("payload"), dict) else {}
    parent = tx.get("parent")
    parent_s: str | None = parent.strip() if isinstance(parent, str) and parent.strip() else None
    pubkey, sk = deterministic_mldsa_keypair(label=(label or signer))
    chain_id = str(tx.get("chain_id") or "weall-testnet-v1")
    network_id = str(tx.get("network_id") or "weall-public-observer-testnet-v1")
    msg = canonical_tx_message(
        chain_id=chain_id,
        network_id=network_id,
        sig_profile=PQ_MLDSA_V1,
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        parent=parent_s,
    )
    sig_hex = sign_signature_for_profile(sig_profile=PQ_MLDSA_V1, message=msg, privkey=sk, encoding="hex")
    out = dict(tx)
    out["chain_id"] = chain_id
    out["network_id"] = network_id
    out["sig_profile"] = PQ_MLDSA_V1
    out["signature"] = {"alg": "ML-DSA", "pubkey": pubkey, "sig": sig_hex}
    out["pubkey"] = pubkey
    out["sig"] = sig_hex
    return out
