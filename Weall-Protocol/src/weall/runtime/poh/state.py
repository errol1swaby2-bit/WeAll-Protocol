from __future__ import annotations

"""Canonical Proof-of-Humanity account status helpers.

This module is intentionally consensus-safe: it is pure state normalization and
mutation logic with no wall-clock, environment, network, SMTP, DNS, or provider
lookups. Domain appliers should use this module instead of reading or writing
``accounts[account_id]['poh_tier']`` directly.
"""

from typing import Any, Literal

Json = dict[str, Any]

POH_STATUS_ACTIVE = "active"
POH_STATUS_EXPIRED = "expired"
POH_STATUS_REVOKED = "revoked"
POH_STATUS_SUSPENDED = "suspended"
POH_STATUS_UNDER_CHALLENGE = "under_challenge"

PohStatus = Literal[
    "active",
    "expired",
    "revoked",
    "suspended",
    "under_challenge",
]

MAX_USER_FACING_POH_TIER = 2


def v2_poh_tier(value: Any) -> int:
    """Normalize a stored value into the v2 two-tier model for read surfaces.

    Historical imported state may still contain values above Tier 2. Read-side
    normalization clamps those values to Tier 2 so old snapshots cannot re-create
    a user-facing third tier. Write paths must use ``require_valid_poh_tier`` and
    must never persist a value above Tier 2.
    """

    return max(0, min(MAX_USER_FACING_POH_TIER, _as_int(value, 0)))


def require_valid_poh_tier(value: Any) -> int:
    """Return a canonical PoH tier or fail closed for invalid writes."""

    tier = _as_int(value, 0)
    if tier < 0 or tier > MAX_USER_FACING_POH_TIER:
        raise ValueError("invalid_poh_tier")
    return tier


def poh_tier_label(value: Any) -> str:
    tier = v2_poh_tier(value)
    if tier >= 2:
        return "Live Verified Human"
    if tier == 1:
        return "Async Verified Human"
    return "Unverified Account"


VALID_POH_STATUSES: frozenset[str] = frozenset(
    {
        POH_STATUS_ACTIVE,
        POH_STATUS_EXPIRED,
        POH_STATUS_REVOKED,
        POH_STATUS_SUSPENDED,
        POH_STATUS_UNDER_CHALLENGE,
    }
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


def poh_root(state: Json) -> Json:
    root = state.get("poh")
    if not isinstance(root, dict):
        root = {}
        state["poh"] = root
    return root


def account_status_root(state: Json) -> Json:
    root = poh_root(state)
    statuses = root.get("account_status")
    if not isinstance(statuses, dict):
        statuses = {}
        root["account_status"] = statuses
    return statuses


def _legacy_account_tier(state: Json, account_id: str) -> int:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return 0
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        return 0
    return _as_int(acct.get("poh_tier"), 0)


def canonical_account_poh_status(state: Json, account_id: str) -> Json:
    """Return a normalized canonical AccountPoHStatus view.

    During migration, a missing canonical record is derived from the legacy
    account-level ``poh_tier`` field. Callers that want to persist a status
    should use ``set_account_poh_status``.
    """

    account_id = _as_str(account_id)
    statuses = account_status_root(state)
    rec = statuses.get(account_id)
    if not isinstance(rec, dict):
        tier = _legacy_account_tier(state, account_id)
        status = POH_STATUS_ACTIVE if tier > 0 else POH_STATUS_EXPIRED
        return {
            "account_id": account_id,
            "poh_tier": v2_poh_tier(tier),
            "status": status,
            "verified_at_height": None,
            "expires_at_height": None,
            "proof_commitment": None,
            "issuer_oracle_id": None,
            "last_updated_height": _as_int(state.get("height"), 0),
            "poh_tier_label": poh_tier_label(tier),
        }

    status = _as_str(rec.get("status") or POH_STATUS_EXPIRED)
    if status not in VALID_POH_STATUSES:
        status = POH_STATUS_EXPIRED

    return {
        "account_id": _as_str(rec.get("account_id") or account_id),
        "poh_tier": v2_poh_tier(rec.get("poh_tier")),
        "status": status,
        "verified_at_height": rec.get("verified_at_height"),
        "expires_at_height": rec.get("expires_at_height"),
        "proof_commitment": rec.get("proof_commitment"),
        "issuer_oracle_id": rec.get("issuer_oracle_id"),
        "last_updated_height": _as_int(rec.get("last_updated_height"), 0),
        "poh_tier_label": poh_tier_label(rec.get("poh_tier")),
    }


def effective_poh_tier(state: Json, account_id: str, *, at_height: int | None = None) -> int:
    rec = canonical_account_poh_status(state, account_id)
    status = _as_str(rec.get("status") or POH_STATUS_EXPIRED)
    if status != POH_STATUS_ACTIVE:
        return 0
    expires_at = rec.get("expires_at_height")
    if expires_at is not None:
        try:
            height = _as_int(state.get("height"), 0) if at_height is None else int(at_height)
            if height > int(expires_at):
                return 0
        except Exception:
            return 0
    return v2_poh_tier(rec.get("poh_tier"))


def set_account_poh_status(
    state: Json,
    *,
    account_id: str,
    poh_tier: int,
    status: str = POH_STATUS_ACTIVE,
    verified_at_height: int | None = None,
    expires_at_height: int | None = None,
    proof_commitment: str | None = None,
    issuer_oracle_id: str | None = None,
    last_updated_height: int | None = None,
    mirror_legacy_account_field: bool = True,
) -> Json:
    account_id = _as_str(account_id)
    if not account_id:
        raise ValueError("missing_account_id")
    status_norm = _as_str(status or POH_STATUS_ACTIVE)
    if status_norm not in VALID_POH_STATUSES:
        raise ValueError("invalid_poh_status")

    height = _as_int(state.get("height"), 0) if last_updated_height is None else int(last_updated_height)
    tier = require_valid_poh_tier(poh_tier)
    rec: Json = {
        "account_id": account_id,
        "poh_tier": tier,
        "status": status_norm,
        "verified_at_height": verified_at_height,
        "expires_at_height": expires_at_height,
        "proof_commitment": proof_commitment,
        "issuer_oracle_id": issuer_oracle_id,
        "last_updated_height": height,
    }
    account_status_root(state)[account_id] = rec

    if mirror_legacy_account_field:
        accounts = state.get("accounts")
        if isinstance(accounts, dict):
            acct = accounts.get(account_id)
            if isinstance(acct, dict):
                acct["poh_tier"] = max(v2_poh_tier(acct.get("poh_tier")), tier)
                acct["poh_status"] = status_norm

    return rec


def revoke_account_poh_status(
    state: Json,
    *,
    account_id: str,
    reason: str = "revoked",
    last_updated_height: int | None = None,
) -> Json:
    current = canonical_account_poh_status(state, account_id)
    rec = set_account_poh_status(
        state,
        account_id=account_id,
        poh_tier=0,
        status=POH_STATUS_REVOKED,
        verified_at_height=current.get("verified_at_height"),
        expires_at_height=current.get("expires_at_height"),
        proof_commitment=current.get("proof_commitment"),
        issuer_oracle_id=current.get("issuer_oracle_id"),
        last_updated_height=last_updated_height,
    )
    rec["revocation_reason"] = _as_str(reason or "revoked")
    accounts = state.get("accounts")
    if isinstance(accounts, dict) and isinstance(accounts.get(account_id), dict):
        accounts[account_id]["poh_tier"] = 0
        accounts[account_id]["poh_status"] = POH_STATUS_REVOKED
    return rec
