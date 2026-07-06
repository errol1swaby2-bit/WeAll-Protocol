from __future__ import annotations

"""Profile-aware account key record helpers."""

import hashlib
import json
from typing import Any

from weall.crypto.signature_profiles import (
    LEGACY_ED25519_V1,
    PQ_MLDSA_V1,
    mode_requires_explicit_sig_profile,
    normalize_signature_profile_id,
    profile_allowed_for_context,
)

Json = dict[str, Any]


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id_for_record(record: Json) -> str:
    return hashlib.sha256(_canon(record)).hexdigest()[:32]


def mldsa_account_key_record(*, pubkey: str, created_height: int = 0, active: bool = True) -> Json:
    base: Json = {
        "sig_profile": PQ_MLDSA_V1,
        "pubkeys": {"mldsa": str(pubkey).strip()},
        "active": bool(active),
        "created_height": int(created_height),
        "revoked_height": None,
    }
    base["key_id"] = key_id_for_record(base)
    return base


def legacy_ed25519_account_key_record(*, pubkey: str, created_height: int = 0, active: bool = True) -> Json:
    base: Json = {
        "sig_profile": LEGACY_ED25519_V1,
        "pubkey": str(pubkey).strip(),
        "active": bool(active),
        "created_height": int(created_height),
        "revoked_height": None,
    }
    base["key_id"] = key_id_for_record(base)
    return base


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
        if mode_requires_explicit_sig_profile():
            return False, "account_key_missing_sig_profile"
        profile = LEGACY_ED25519_V1
    ok_profile, reason = profile_allowed_for_context(profile, chain_config=chain_config, require_verifier=require_verifier)
    if not ok_profile:
        return False, reason
    if profile == PQ_MLDSA_V1:
        pubkeys = record.get("pubkeys") if isinstance(record.get("pubkeys"), dict) else {}
        if not str(pubkeys.get("mldsa") or "").strip():
            return False, "account_key_missing_mldsa_pubkey"
    elif profile == LEGACY_ED25519_V1:
        if not str(record.get("pubkey") or "").strip():
            return False, "account_key_missing_ed25519_pubkey"
    else:
        return False, "account_key_unsupported_profile"
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
