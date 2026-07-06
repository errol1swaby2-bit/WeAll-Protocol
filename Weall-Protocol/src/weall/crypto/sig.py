from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from weall.crypto.pq_mldsa import mldsa65_public_key_from_seed, sign_mldsa65, verify_mldsa65_signature
from weall.crypto.signature_profiles import (
    LEGACY_ED25519_V1,
    PQ_MLDSA_V1,
    default_signature_profile_for_mode,
    mode_requires_explicit_sig_profile,
    normalize_signature_profile_id,
    profile_allowed_for_context,
)

Json = dict[str, Any]


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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def strict_tx_sig_domain_enabled() -> bool:
    """Return True when tx signatures must include chain_id.

    Production default is fail-closed. Legacy no-chain-id signatures remain
    available only outside prod, or when explicitly re-enabled via
    WEALL_ALLOW_LEGACY_SIG_DOMAIN=1.
    """
    mode = str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"
    allow_legacy = _env_bool("WEALL_ALLOW_LEGACY_SIG_DOMAIN", default=(mode != "prod"))
    return not allow_legacy


def canonical_tx_message(
    *,
    chain_id: str | None = None,
    network_id: str | None = None,
    domain_separator: str | None = None,
    object_kind: str = "tx",
    sig_profile: str | None = None,
    activation_height: int | None = None,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    parent: str | None = None,
) -> bytes:
    """Canonical tx signing bytes with explicit protocol context.

    Legacy callers may omit ``sig_profile`` and ``network_id`` outside strict
    closed/public testnet mode.  Strict modes require the caller to include a
    profile through tx admission before verification is attempted.
    """

    obj: Json = {
        **({"chain_id": str(chain_id)} if (isinstance(chain_id, str) and chain_id.strip()) else {}),
        **({"network_id": str(network_id)} if (isinstance(network_id, str) and network_id.strip()) else {}),
        "domain_separator": str(domain_separator or "weall.tx.v1"),
        "object_kind": str(object_kind or "tx"),
        **({"sig_profile": normalize_signature_profile_id(sig_profile)} if normalize_signature_profile_id(sig_profile) else {}),
        **({"activation_height": int(activation_height)} if activation_height is not None else {}),
        "tx_type": str(tx_type),
        "signer": str(signer),
        "nonce": int(nonce),
        "payload": payload if isinstance(payload, dict) else {},
    }
    if parent is not None:
        obj["parent"] = str(parent)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def verify_ed25519_signature(*, message: bytes, sig: str, pubkey: str) -> bool:
    try:
        sig_b = _decode_bytes(sig)
        pk_b = _decode_bytes(pubkey)
        key = Ed25519PublicKey.from_public_bytes(pk_b)
        key.verify(sig_b, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _extract_signature_fields(tx: Json) -> tuple[str, str, str, str]:
    profile = normalize_signature_profile_id(tx.get("sig_profile"))
    nested = tx.get("signature") if isinstance(tx.get("signature"), dict) else {}
    alg = str(nested.get("alg") or tx.get("sig_alg") or "").strip()
    pubkey = str(nested.get("pubkey") or tx.get("pubkey") or "").strip()
    sig = str(nested.get("sig") or tx.get("sig") or "").strip()
    return profile, alg, pubkey, sig


def sign_tx_envelope_dict(*, tx: Json, privkey: str, encoding: str = "hex") -> Json:
    """Return a copy of tx with signature metadata populated.

    ``pq-mldsa-v1`` is used when the tx already requests it or when strict
    controlled/public testnet mode is selected.  In ordinary dev/prod service
    tests, legacy Ed25519 compatibility remains unless a profile is supplied.
    """
    tx_type = str(tx.get("tx_type") or tx.get("type") or "")
    signer = str(tx.get("signer") or "")
    nonce = int(tx.get("nonce") or 0)
    payload = tx.get("payload") if isinstance(tx.get("payload"), dict) else {}
    parent = tx.get("parent")
    chain_id = tx.get("chain_id")
    network_id = tx.get("network_id")
    sig_profile = normalize_signature_profile_id(tx.get("sig_profile"))
    if not sig_profile:
        sig_profile = default_signature_profile_for_mode()

    msg = canonical_tx_message(
        chain_id=str(chain_id) if isinstance(chain_id, str) else None,
        network_id=str(network_id) if isinstance(network_id, str) else None,
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        parent=parent,
        sig_profile=sig_profile,
    )

    out = dict(tx)
    out["tx_type"] = tx_type
    out["signer"] = signer
    out["nonce"] = nonce
    out["payload"] = payload
    out["sig_profile"] = sig_profile
    if parent is not None:
        out["parent"] = str(parent)
    if isinstance(chain_id, str) and chain_id.strip():
        out["chain_id"] = chain_id.strip()
    if isinstance(network_id, str) and network_id.strip():
        out["network_id"] = network_id.strip()

    if sig_profile == PQ_MLDSA_V1:
        sig = sign_signature_for_profile(sig_profile=sig_profile, message=msg, privkey=privkey, encoding=encoding)
        pubkey = str(out.get("pubkey") or "").strip() or public_key_for_private_key_profile(
            sig_profile=sig_profile, privkey=privkey, encoding=encoding
        )
        out["signature"] = {"alg": "ML-DSA", "pubkey": pubkey, "sig": sig}
        out["sig"] = sig
        out["pubkey"] = pubkey
        return out
    if sig_profile == LEGACY_ED25519_V1:
        sig = sign_signature_for_profile(sig_profile=sig_profile, message=msg, privkey=privkey, encoding=encoding)
        out["sig"] = sig
        return out
    raise ValueError("unsupported_signature_profile")


def sign_ed25519(*, message: bytes, privkey: str, encoding: str = "hex") -> str:
    """Sign a message with an Ed25519 private key.

    privkey: hex or base64/base64url string representing 32-byte seed or 64-byte private key.
    encoding: "hex" (default) or "b64".
    """
    pk_b = _decode_bytes(privkey)

    if len(pk_b) == 64:
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


def sign_signature_for_profile(*, sig_profile: str, message: bytes, privkey: str, encoding: str = "hex") -> str:
    profile = normalize_signature_profile_id(sig_profile)
    if profile == LEGACY_ED25519_V1:
        return sign_ed25519(message=message, privkey=privkey, encoding=encoding)
    if profile == PQ_MLDSA_V1:
        return sign_mldsa65(message=message, privkey=privkey, encoding=encoding)
    raise ValueError("unsupported_signature_profile")


def public_key_for_private_key_profile(*, sig_profile: str, privkey: str, encoding: str = "hex") -> str:
    profile = normalize_signature_profile_id(sig_profile)
    if profile == PQ_MLDSA_V1:
        return mldsa65_public_key_from_seed(privkey=privkey, encoding=encoding)
    raise ValueError("public_key_derivation_not_supported_for_profile")


def extract_active_account_pubkeys(ledger: Json, account_id: str, *, sig_profile: str | None = None) -> list[str]:
    """
    STRICT schema:

      ledger["accounts"][account_id]["keys"] = [
        {"pubkey": "<hex|b64>", "active": true|false},
        {"sig_profile": "pq-mldsa-v1", "pubkeys": {"mldsa": "..."}, "active": true},
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

    wanted_profile = normalize_signature_profile_id(sig_profile)
    keys = acct.get("keys")
    if not isinstance(keys, list):
        return []

    out: list[str] = []
    seen = set()

    for rec in keys:
        if not isinstance(rec, dict):
            continue
        if not rec.get("active", True):
            continue
        rec_profile = normalize_signature_profile_id(rec.get("sig_profile"))
        if wanted_profile and rec_profile and rec_profile != wanted_profile:
            continue
        pk = None
        if rec_profile == PQ_MLDSA_V1:
            pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), dict) else {}
            pk = pubkeys.get("mldsa")
        if pk is None:
            pk = rec.get("pubkey")
        if isinstance(pk, str):
            pk = pk.strip()
            if pk and pk not in seen:
                seen.add(pk)
                out.append(pk)

    return out


def verify_signature_for_profile(*, sig_profile: str, message: bytes, sig: str, pubkey: str) -> bool:
    profile = normalize_signature_profile_id(sig_profile)
    if profile == LEGACY_ED25519_V1:
        return verify_ed25519_signature(message=message, sig=sig, pubkey=pubkey)
    if profile == PQ_MLDSA_V1:
        return verify_mldsa65_signature(message=message, sig=sig, pubkey=pubkey)
    return False


def verify_tx_sig_against_any_key(
    *,
    ledger: Json,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    sig: str,
    parent: str | None = None,
    chain_id: str | None = None,
    network_id: str | None = None,
    sig_profile: str | None = None,
    chain_config: Json | None = None,
) -> tuple[bool, dict[str, Any]]:
    profile = normalize_signature_profile_id(sig_profile)
    if not profile:
        if mode_requires_explicit_sig_profile():
            return False, {"reason": "missing_signature_profile"}
        profile = LEGACY_ED25519_V1
    allowed, reason = profile_allowed_for_context(profile, chain_config=chain_config, require_verifier=True)
    if not allowed:
        return False, {"reason": reason, "sig_profile": profile}

    keys = extract_active_account_pubkeys(ledger, signer, sig_profile=profile)
    if not keys:
        return False, {"reason": "no_active_keys"}

    chain_id2 = str(chain_id).strip() if isinstance(chain_id, str) else ""
    if strict_tx_sig_domain_enabled() and not chain_id2:
        return False, {"reason": "missing_chain_id"}

    msg_candidates: list[bytes] = []
    if chain_id2:
        msg_candidates.append(
            canonical_tx_message(
                chain_id=chain_id2,
                network_id=network_id,
                sig_profile=profile,
                tx_type=tx_type,
                signer=signer,
                nonce=nonce,
                payload=payload,
                parent=parent,
            )
        )
    if not strict_tx_sig_domain_enabled():
        msg_candidates.append(
            canonical_tx_message(
                sig_profile=profile,
                tx_type=tx_type,
                signer=signer,
                nonce=nonce,
                payload=payload,
                parent=parent,
            )
        )

    for pk in keys:
        for msg in msg_candidates:
            if verify_signature_for_profile(sig_profile=profile, message=msg, sig=sig, pubkey=pk):
                return True, {"pubkey": pk, "sig_profile": profile}

    return False, {"reason": "invalid_signature", "sig_profile": profile}
