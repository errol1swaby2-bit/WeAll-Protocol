from __future__ import annotations

import hashlib
from typing import Any, Mapping

Json = dict[str, Any]

_SESSION_KEY_DOMAIN = b"weall/session-key/v1\x00"
SESSION_KEY_HASH_PREFIX = "skh:v1:"


def session_key_hash(session_key: Any) -> str:
    """Return the canonical hash for an opaque bearer session key.

    Session keys are bearer secrets.  Consensus/account state should store only
    a domain-separated hash, while clients continue sending the raw key in the
    private API header.
    """

    raw = str(session_key or "").strip().encode("utf-8")
    return hashlib.sha256(_SESSION_KEY_DOMAIN + raw).hexdigest()


def session_record_key(session_key: Any) -> str:
    return f"{SESSION_KEY_HASH_PREFIX}{session_key_hash(session_key)}"


def is_hashed_session_key(key: Any) -> bool:
    return str(key or "").startswith(SESSION_KEY_HASH_PREFIX)


def session_record_for(sessions: Mapping[str, Any] | None, session_key: Any) -> Json | None:
    """Resolve a session record by raw key using hashed storage first.

    Legacy raw-key lookup is retained only for compatibility with historical
    tests/state snapshots and should not be used for new writes.
    """

    if not isinstance(sessions, Mapping):
        return None
    hashed_key = session_record_key(session_key)
    rec = sessions.get(hashed_key)
    if isinstance(rec, dict):
        return rec
    legacy = sessions.get(str(session_key or "").strip())
    return legacy if isinstance(legacy, dict) else None


def store_session_record(sessions: Json, session_key: Any, record: Mapping[str, Any]) -> str:
    key = session_record_key(session_key)
    out = dict(record)
    out["session_key_hash"] = session_key_hash(session_key)
    out["key_format"] = "sha256-domain-v1"
    sessions[key] = out
    return key


def revoke_session_record(sessions: Json, session_key: Any) -> Json | None:
    key = session_record_key(session_key)
    rec = sessions.get(key)
    if isinstance(rec, dict):
        return rec
    legacy_key = str(session_key or "").strip()
    legacy = sessions.get(legacy_key)
    return legacy if isinstance(legacy, dict) else None
