# src/weall/crypto/sig.py
from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey

Json = Dict[str, Any]


def _decode_bytes(s: str) -> bytes:
    s = s.strip()
    if not s:
        raise ValueError("empty string")
    # hex
    try:
        return bytes.fromhex(s)
    except Exception:
        pass
    # base64 / base64url
    try:
        padding = "=" * (-len(s) % 4)
        s2 = (s + padding).replace("-", "+").replace("_", "/")
        return base64.b64decode(s2)
    except Exception as e:
        raise ValueError("not hex or base64") from e


def canonical_tx_message(
    *,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    parent: Optional[str] = None,
) -> bytes:
    obj: Json = {
        "tx_type": str(tx_type),
        "signer": str(signer),
        "nonce": int(nonce),
        "payload": payload if isinstance(payload, dict) else {},
    }
    if parent is not None:
        obj["parent"] = str(parent)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_ed25519_signature(*, message: bytes, sig: str, pubkey: str) -> bool:
    try:
        sig_b = _decode_bytes(sig)
        pk_b = _decode_bytes(pubkey)
        key = Ed25519PublicKey.from_public_bytes(pk_b)
        key.verify(sig_b, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_tx_envelope_dict(*, tx: Json, privkey: str, encoding: str = "hex") -> Json:
    """Return a copy of tx with its 'sig' field populated.

    Expected shape (extra keys allowed):
      {
        "tx_type": str,
        "signer": str,
        "nonce": int,
        "payload": dict,
        "parent": Optional[str]
      }
    """
    tx_type = str(tx.get("tx_type") or tx.get("type") or "")
    signer = str(tx.get("signer") or "")
    nonce = int(tx.get("nonce") or 0)
    payload = tx.get("payload") if isinstance(tx.get("payload"), dict) else {}
    parent = tx.get("parent")

    msg = canonical_tx_message(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, parent=parent)
    sig = sign_ed25519(message=msg, privkey=privkey, encoding=encoding)

    out = dict(tx)
    out["tx_type"] = tx_type
    out["signer"] = signer
    out["nonce"] = nonce
    out["payload"] = payload
    out["sig"] = sig
    if parent is not None:
        out["parent"] = str(parent)
    return out


def sign_ed25519(*, message: bytes, privkey: str, encoding: str = "hex") -> str:
    """Sign a message with an Ed25519 private key.

    privkey: hex or base64/base64url string representing 32-byte seed or 64-byte private key.
    encoding: "hex" (default) or "b64".
    """
    pk_b = _decode_bytes(privkey)

    # cryptography expects a 32-byte seed for from_private_bytes.
    if len(pk_b) == 64:
        # Many libs store 64-byte expanded private keys; Ed25519PrivateKey.from_private_bytes
        # accepts the 32-byte seed. Use the first 32 bytes as a pragmatic default.
        pk_b = pk_b[:32]

    if len(pk_b) != 32:
        raise ValueError("ed25519 privkey must be 32-byte seed (or 64-byte expanded key)")

    key = Ed25519PrivateKey.from_private_bytes(pk_b)
    sig_b = key.sign(message)
    if encoding == "hex":
        return sig_b.hex()
    if encoding in {"b64", "base64"}:
        return base64.b64encode(sig_b).decode("ascii")
    raise ValueError("unsupported encoding")


def extract_active_account_pubkeys(ledger: Json, account_id: str) -> List[str]:
    """
    STRICT schema:

      ledger["accounts"][account_id]["keys"] = [
        {"pubkey": "<hex|b64>", "active": true|false},
        ...
      ]

    If the schema does not match, returns [] (caller should treat as no keys).
    """
    accounts = ledger.get("accounts")
    if not isinstance(accounts, dict):
        return []
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        return []

    keys = acct.get("keys")
    if not isinstance(keys, list):
        return []

    out: List[str] = []
    seen = set()

    for rec in keys:
        if not isinstance(rec, dict):
            continue
        if not rec.get("active", True):
            continue
        pk = rec.get("pubkey")
        if isinstance(pk, str):
            pk = pk.strip()
            if pk and pk not in seen:
                seen.add(pk)
                out.append(pk)

    return out


def verify_tx_sig_against_any_key(
    *,
    ledger: Json,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    sig: str,
    parent: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    keys = extract_active_account_pubkeys(ledger, signer)
    if not keys:
        return False, {"reason": "no_active_keys"}

    msg = canonical_tx_message(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, parent=parent)
    for pk in keys:
        if verify_ed25519_signature(message=msg, sig=sig, pubkey=pk):
            return True, {"pubkey": pk}

    return False, {"reason": "invalid_signature"}
