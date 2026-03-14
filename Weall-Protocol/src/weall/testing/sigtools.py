from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from weall.crypto.sig import canonical_tx_message

Json = Dict[str, Any]


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def deterministic_ed25519_keypair(*, label: str) -> Tuple[str, Ed25519PrivateKey]:
    """Deterministically derive an Ed25519 keypair from a stable label.

    TEST ONLY.

    Returns:
      (pubkey_hex, private_key)
    """
    seed = _sha256(("weall-test-ed25519:" + (label or "")).encode("utf-8"))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return pk_hex, sk


def ensure_account_has_test_key(accounts: Json, *, account_id: str) -> str:
    """Ensure accounts[account_id].keys includes one active test pubkey.

    Returns the pubkey hex.
    """
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

    # If there is already an active key, keep it.
    for rec in keys:
        if isinstance(rec, dict) and rec.get("active", True):
            pk = rec.get("pubkey")
            if isinstance(pk, str) and pk.strip():
                return pk.strip()

    pubkey_hex, _ = deterministic_ed25519_keypair(label=account_id)
    keys.append({"pubkey": pubkey_hex, "active": True})
    return pubkey_hex


def sign_tx_dict(tx: Json, *, label: Optional[str] = None) -> Json:
    """Return tx with a real Ed25519 signature (hex), deterministically derived.

    - Signing key derived from `label` if provided, else from tx['signer'].
    - Signature over canonical_tx_message(...)
    """
    if not isinstance(tx, dict):
        raise TypeError("tx must be a dict")

    tx_type = str(tx.get("tx_type") or "").strip()
    signer = str(tx.get("signer") or "").strip()
    nonce = int(tx.get("nonce") or 0)
    payload = tx.get("payload")
    parent = tx.get("parent")

    if not isinstance(payload, dict):
        payload = {}

    parent_s: Optional[str] = None
    if isinstance(parent, str) and parent.strip():
        parent_s = parent.strip()

    _, sk = deterministic_ed25519_keypair(label=(label or signer))
    msg = canonical_tx_message(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, parent=parent_s)
    sig_hex = sk.sign(msg).hex()

    out = dict(tx)
    out["sig"] = sig_hex
    return out
