from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

Json = dict[str, Any]

SNAPSHOT_VERSION = 1
SNAPSHOT_TYPE = "weall_email_oracle_authority_snapshot"
SNAPSHOT_SIGNATURE_DOMAIN = "weall-oracle-authority-snapshot-v1"
DEFAULT_SNAPSHOT_TTL_MS = 60_000


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def snapshot_signing_payload(snapshot: Json) -> Json:
    return {k: v for k, v in snapshot.items() if k not in {"snapshot_hash", "signatures"}}


def snapshot_hash(snapshot_or_payload: Json) -> str:
    return hashlib.sha256(canonical_json(snapshot_signing_payload(snapshot_or_payload)).encode("utf-8")).hexdigest()


def snapshot_signature_message(snapshot_or_payload: Json) -> bytes:
    payload = snapshot_signing_payload(snapshot_or_payload)
    return f"{SNAPSHOT_SIGNATURE_DOMAIN}\n{canonical_json(payload)}\n".encode("utf-8")


def sign_authority_snapshot(
    snapshot: Json,
    *,
    signer: str,
    pubkey: str,
    privkey_hex: str,
) -> Json:
    """Return snapshot with snapshot_hash and one Ed25519 authority signature.

    The private key is never returned. The signature binds the exact canonical
    authority payload, including chain_id, genesis hash, tx_index hash, height,
    state_root, validator metadata, expiry, and registry records.
    """

    out = dict(snapshot_signing_payload(snapshot))
    out["snapshot_hash"] = snapshot_hash(out)
    signing_key = SigningKey(bytes.fromhex(str(privkey_hex or "").strip()))
    sig = signing_key.sign(snapshot_signature_message(out)).signature.hex()
    out["signatures"] = [
        {
            "signer": str(signer or "").strip(),
            "pubkey": str(pubkey or "").strip().lower(),
            "signature": sig,
        }
    ]
    return out


def verify_authority_snapshot_signature(snapshot: Json, *, trusted_pubkeys: set[str] | list[str] | tuple[str, ...]) -> bool:
    expected_hash = str(snapshot.get("snapshot_hash") or "").strip().lower()
    if not expected_hash or expected_hash != snapshot_hash(snapshot):
        return False
    trusted = {str(pk or "").strip().lower() for pk in trusted_pubkeys if str(pk or "").strip()}
    if not trusted:
        return False
    signatures = snapshot.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False
    msg = snapshot_signature_message(snapshot)
    for item in signatures:
        sig = item if isinstance(item, dict) else {}
        pubkey = str(sig.get("pubkey") or "").strip().lower()
        signature = str(sig.get("signature") or "").strip().lower()
        if not pubkey or pubkey not in trusted or not signature:
            continue
        try:
            VerifyKey(bytes.fromhex(pubkey)).verify(msg, bytes.fromhex(signature))
            return True
        except (BadSignatureError, ValueError):
            continue
    return False


def now_ms() -> int:
    return int(time.time() * 1000)
