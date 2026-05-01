from __future__ import annotations

"""Consensus-visible oracle registry helpers.

Normal nodes verify oracle attestations from chain state only. These helpers do
not read process environment variables and do not call network services.
"""

import hashlib
from typing import Any

Json = dict[str, Any]

ORACLE_STATUS_ACTIVE = "active"
ORACLE_STATUS_PENDING = "pending"
ORACLE_STATUS_SUSPENDED = "suspended"
ORACLE_STATUS_REVOKED = "revoked"

ORACLE_TYPE_POH_EMAIL_TIER1 = "poh_email_tier1"
ORACLE_TYPE_POH_ASYNC_TIER1 = "poh_async_tier1"
ORACLE_TYPE_POH_LIVE_TIER2 = "poh_live_tier2"

VALID_ORACLE_TYPES: frozenset[str] = frozenset(
    {ORACLE_TYPE_POH_EMAIL_TIER1, ORACLE_TYPE_POH_ASYNC_TIER1, ORACLE_TYPE_POH_LIVE_TIER2}
)
VALID_ORACLE_STATUSES: frozenset[str] = frozenset(
    {ORACLE_STATUS_ACTIVE, ORACLE_STATUS_PENDING, ORACLE_STATUS_SUSPENDED, ORACLE_STATUS_REVOKED}
)


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def sha256_hex_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def registry_root(state: Json) -> Json:
    root = state.get("oracle_registry")
    if not isinstance(root, dict):
        root = {}
        state["oracle_registry"] = root
    oracles = root.get("oracles")
    if not isinstance(oracles, dict):
        oracles = {}
        root["oracles"] = oracles
    return root


def oracles_root(state: Json) -> Json:
    return registry_root(state)["oracles"]


def canonical_oracle_record(record: Json) -> Json:
    oracle_type = _as_str(record.get("oracle_type") or ORACLE_TYPE_POH_EMAIL_TIER1)
    if oracle_type not in VALID_ORACLE_TYPES:
        oracle_type = ORACLE_TYPE_POH_EMAIL_TIER1
    status = _as_str(record.get("status") or ORACLE_STATUS_PENDING)
    if status not in VALID_ORACLE_STATUSES:
        status = ORACLE_STATUS_PENDING
    return {
        "oracle_id": _as_str(record.get("oracle_id") or ""),
        "operator_account": _as_str(record.get("operator_account") or ""),
        "oracle_type": oracle_type,
        "oracle_pubkey": _as_str(record.get("oracle_pubkey") or "").lower(),
        "status": status,
        "endpoint_commitment": _as_str(record.get("endpoint_commitment") or ""),
        "mail_domain_hash": _as_str(record.get("mail_domain_hash") or ""),
        "registered_at_height": _as_int(record.get("registered_at_height"), 0),
        "suspended_at_height": record.get("suspended_at_height"),
        "rotated_from_oracle_id": record.get("rotated_from_oracle_id"),
        "valid_from_height": _as_int(record.get("valid_from_height"), _as_int(record.get("registered_at_height"), 0)),
        "valid_until_height": record.get("valid_until_height"),
    }


def get_oracle_record(state: Json, oracle_id: str) -> Json | None:
    rec = oracles_root(state).get(_as_str(oracle_id))
    if not isinstance(rec, dict):
        return None
    return canonical_oracle_record(rec)


def put_oracle_record(state: Json, record: Json) -> Json:
    rec = canonical_oracle_record(record)
    oracle_id = _as_str(rec.get("oracle_id") or "")
    if not oracle_id:
        raise ValueError("missing_oracle_id")
    if not rec.get("operator_account"):
        raise ValueError("missing_operator_account")
    if not rec.get("oracle_pubkey"):
        raise ValueError("missing_oracle_pubkey")
    oracles_root(state)[oracle_id] = rec
    return rec


def require_active_oracle(
    state: Json,
    *,
    oracle_id: str,
    oracle_type: str = ORACLE_TYPE_POH_EMAIL_TIER1,
    at_height: int | None = None,
) -> Json:
    rec = get_oracle_record(state, oracle_id)
    if rec is None:
        raise ValueError("unknown_oracle")
    if _as_str(rec.get("oracle_type")) != _as_str(oracle_type):
        raise ValueError("oracle_type_mismatch")
    if _as_str(rec.get("status")) != ORACLE_STATUS_ACTIVE:
        raise ValueError("oracle_not_active")
    height = _as_int(at_height, 0) if at_height is not None else _as_int(state.get("height"), 0)
    valid_from = _as_int(rec.get("valid_from_height"), _as_int(rec.get("registered_at_height"), 0))
    valid_until = rec.get("valid_until_height")
    if height < valid_from:
        raise ValueError("oracle_not_yet_valid")
    if valid_until is not None and height > _as_int(valid_until, -1):
        raise ValueError("oracle_key_expired")
    return rec


def suspend_oracle(state: Json, *, oracle_id: str, height: int | None = None) -> Json:
    rec = get_oracle_record(state, oracle_id)
    if rec is None:
        raise ValueError("unknown_oracle")
    rec["status"] = ORACLE_STATUS_SUSPENDED
    rec["suspended_at_height"] = _as_int(state.get("height"), 0) if height is None else int(height)
    oracles_root(state)[_as_str(oracle_id)] = rec
    return rec
