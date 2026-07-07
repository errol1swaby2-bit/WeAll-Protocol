from __future__ import annotations

"""Post-quantum account key record helpers."""

import hashlib
import json
from typing import Any

from weall.crypto.signature_profiles import PQ_MLDSA_V1, normalize_signature_profile_id, profile_allowed_for_context

Json = dict[str, Any]


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id_for_record(record: Json) -> str:
    return hashlib.sha256(_canon(record)).hexdigest()[:32]


def _mk_key_id(profile: str, pubkey: str) -> str:
    h = hashlib.sha256(f"{profile}:{pubkey}".encode("utf-8")).hexdigest()
    return f"k:{h[:16]}"


def mldsa_account_key_record(*, pubkey: str, created_height: int = 0, active: bool = True, key_type: str = "main") -> Json:
    pk = str(pubkey).strip()
    return {
        "key_id": _mk_key_id(PQ_MLDSA_V1, pk),
        "sig_profile": PQ_MLDSA_V1,
        "pubkeys": {"mldsa": pk},
        "key_type": str(key_type or "main"),
        "active": bool(active),
        "revoked": False,
        "created_height": int(created_height),
        "revoked_height": None,
        "revoked_at": None,
    }


def account_key_record_from_payload(
    payload: Json,
    *,
    created_height: int = 0,
    default_profile: str = PQ_MLDSA_V1,
    key_type: str = "main",
) -> Json:
    profile = normalize_signature_profile_id(payload.get("sig_profile") or default_profile)
    if profile != PQ_MLDSA_V1:
        return {"sig_profile": profile, "active": True, "created_height": int(created_height)}
    pubkeys = payload.get("pubkeys") if isinstance(payload.get("pubkeys"), dict) else {}
    pubkey = str(pubkeys.get("mldsa") or payload.get("mldsa_pubkey") or payload.get("pubkey") or "").strip()
    return mldsa_account_key_record(pubkey=pubkey, created_height=created_height, active=True, key_type=key_type)


def account_key_pubkey(record: Any, *, preferred_profile: str = "") -> str:
    if not isinstance(record, dict):
        return ""
    profile = normalize_signature_profile_id(record.get("sig_profile") or preferred_profile or PQ_MLDSA_V1)
    if profile != PQ_MLDSA_V1:
        return ""
    pubkeys = record.get("pubkeys") if isinstance(record.get("pubkeys"), dict) else {}
    return str(pubkeys.get("mldsa") or record.get("pubkey") or "").strip()


def validate_account_key_record(
    record: Any,
    *,
    chain_config: Json | None = None,
    require_verifier: bool = False,
) -> tuple[bool, str]:
    if not isinstance(record, dict):
        return False, "account_key_not_object"
    profile = normalize_signature_profile_id(record.get("sig_profile"))
    if not profile:
        return False, "account_key_missing_sig_profile"
    ok_profile, reason = profile_allowed_for_context(profile, chain_config=chain_config, require_verifier=require_verifier)
    if not ok_profile:
        return False, reason
    if profile != PQ_MLDSA_V1:
        return False, "account_key_unsupported_profile"
    pubkeys = record.get("pubkeys") if isinstance(record.get("pubkeys"), dict) else {}
    if not str(pubkeys.get("mldsa") or record.get("pubkey") or "").strip():
        return False, "account_key_missing_mldsa_pubkey"
    if "created_height" in record:
        try:
            int(record.get("created_height"))
        except Exception:
            return False, "account_key_bad_created_height"
    return True, "ok"


def extract_account_key_profile(record: Any) -> str:
    if not isinstance(record, dict):
        return ""
    return normalize_signature_profile_id(record.get("sig_profile"))
