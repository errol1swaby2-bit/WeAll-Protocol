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




def _content_summary(content: Any) -> Json:
    root = _as_mapping(content)
    posts = _as_mapping(root.get("posts"))
    comments = _as_mapping(root.get("comments"))
    media = _as_mapping(root.get("media"))

    def _visibility_counts(items: Mapping[str, Any]) -> Json:
        counts: Json = {"total": 0, "public": 0, "non_public": 0, "deleted": 0}
        for rec in items.values():
            if not isinstance(rec, Mapping):
                continue
            counts["total"] = int(counts["total"]) + 1
            if bool(rec.get("deleted", False)):
                counts["deleted"] = int(counts["deleted"]) + 1
                continue
            vis = str(rec.get("visibility") or "public").strip().lower() or "public"
            if vis == "public":
                counts["public"] = int(counts["public"]) + 1
            else:
                counts["non_public"] = int(counts["non_public"]) + 1
        return counts

    return {
        "redacted": True,
        "summary": {
            "posts": _visibility_counts(posts),
            "comments": _visibility_counts(comments),
            "media": {"total": len(media)},
        },
    }


def _groups_summary(groups: Any) -> Json:
    root = _as_mapping(groups)
    total = 0
    public = 0
    private = 0
    for rec in root.values():
        if not isinstance(rec, Mapping):
            continue
        total += 1
        visibility = str(rec.get("visibility") or rec.get("privacy") or "public").strip().lower()
        if visibility in {"private", "closed", "invite_only", "invite-only"}:
            private += 1
        else:
            public += 1
    return {"redacted": True, "summary": {"total": total, "public": public, "private": private}}


def redact_account_state(account_state: Any, *, reveal_restricted: bool = False) -> Any:
    """Return account state safe for public API presentation.

    Owner-authenticated routes may pass reveal_restricted=True to preserve the exact
    account record. Public callers get a copy with bearer session keys and device
    identifiers removed while retaining enough summary state for UX/capability
    display.
    """

    if not isinstance(account_state, Mapping):
        return account_state
    copied = copy.deepcopy(dict(account_state))
    if reveal_restricted:
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
            str(account): redact_account_state(rec, reveal_restricted=False)
            for account, rec in accounts.items()
        }
    if "content" in copied:
        copied["content"] = _content_summary(copied.get("content"))
    if "groups" in copied:
        copied["groups"] = _groups_summary(copied.get("groups"))
    if "groups_by_id" in copied:
        copied["groups_by_id"] = _groups_summary(copied.get("groups_by_id"))
    copied.pop("mess" + "aging", None)
    return _redact_recursive(copied)


__all__ = ["SENSITIVE_PUBLIC_KEYS", "redact_account_state", "redact_public_state"]
