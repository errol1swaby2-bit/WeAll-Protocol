from __future__ import annotations

import copy
from typing import Any, Mapping

Json = dict[str, Any]

# Public HTTP snapshots and public account lookups must not become a bearer-token,
# device-fingerprint, or private-evidence disclosure path. Keep this list
# intentionally broad for public responses. Consensus/state storage remains
# unchanged; only API presentation is redacted.
SENSITIVE_PUBLIC_KEYS: frozenset[str] = frozenset(
    {
        "session_key",
        "session_keys",
        "session_secret",
        "secret",
        "secret_key",
        "secret_key_b64",
        "private_key",
        "private_key_b64",
        "private_key_hex",
        "seed_phrase",
        "recovery_secret",
        "raw_response",
        "raw_video",
        "private_notes",
        "juror_private_notes",
        "email",
        "email_hash",
        "phone",
        "phone_number",
        "ip_address",
        "device_fingerprint",
        "browser_fingerprint",
        "government_id",
        "provider_metadata",
        "kyc_metadata",
        "oauth_provider_metadata",
    }
)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _redact_recursive(value: Any) -> Any:
    if isinstance(value, Mapping):
        out: Json = {}
        for key, item in value.items():
            k = str(key)
            if k in SENSITIVE_PUBLIC_KEYS:
                out[k] = {"redacted": True}
                continue
            out[k] = _redact_recursive(item)
        return out
    if isinstance(value, list):
        return [_redact_recursive(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_recursive(item) for item in value]
    return value


def _device_summary(devices: Any) -> Json:
    by_id = _as_mapping(_as_mapping(devices).get("by_id"))
    total = 0
    active = 0
    revoked = 0
    node = 0
    browser = 0
    for rec in by_id.values():
        if not isinstance(rec, Mapping):
            continue
        total += 1
        is_revoked = rec.get("revoked") is True
        if is_revoked:
            revoked += 1
        else:
            active += 1
        typ = str(rec.get("device_type") or "").strip().lower()
        if typ == "node":
            node += 1
        elif typ == "browser":
            browser += 1
    return {
        "redacted": True,
        "summary": {
            "total": total,
            "active": active,
            "revoked": revoked,
            "node": node,
            "browser": browser,
        },
        "by_id": {},
    }


def redact_account_state(account_state: Any, *, reveal_private: bool = False) -> Any:
    """Return account state safe for public API presentation.

    Owner-authenticated routes may pass reveal_private=True to preserve the exact
    account record. Public callers get a copy with bearer session keys and device
    identifiers removed while retaining enough summary state for UX/capability
    display.
    """

    if not isinstance(account_state, Mapping):
        return account_state
    copied = copy.deepcopy(dict(account_state))
    if reveal_private:
        return copied

    copied.pop("session_keys", None)
    if "devices" in copied:
        copied["devices"] = _device_summary(copied.get("devices"))
    return _redact_recursive(copied)


def redact_public_state(state: Any) -> Any:
    """Return a public snapshot with private account/evidence fields redacted."""

    if not isinstance(state, Mapping):
        return state
    copied = copy.deepcopy(dict(state))
    accounts = copied.get("accounts")
    if isinstance(accounts, Mapping):
        copied["accounts"] = {
            str(account): redact_account_state(rec, reveal_private=False)
            for account, rec in accounts.items()
        }
    return _redact_recursive(copied)


__all__ = ["SENSITIVE_PUBLIC_KEYS", "redact_account_state", "redact_public_state"]
