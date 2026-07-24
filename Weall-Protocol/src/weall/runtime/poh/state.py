from __future__ import annotations

"""Canonical Proof-of-Humanity account status helpers.

This module is intentionally consensus-safe: it is pure state normalization and
mutation logic with no wall-clock, environment, network, DNS, or provider
lookups. Domain appliers should use this module instead of reading or writing
``accounts[account_id]['poh_tier']`` directly.
"""

import hashlib
from typing import Any, Literal

from weall.runtime.tier2_responsibility import (
    mark_tier2_responsibilities_for_replacement,
    process_safe_withdrawals,
)

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

# v2 Tier-2 lifecycle constants. These are protocol-height windows, never wall
# clock durations. A Tier-2 award remains active through ``expires_at_height``
# and falls back to Tier 1 before user transactions at the first later height.
TIER2_VALIDITY_BLOCKS = 777_600
TIER2_REVERIFICATION_WINDOW_BLOCKS = 129_600
TIER2_REMINDER_OFFSETS: tuple[int, ...] = (129_600, 86_400, 43_200, 14_400, 4_320)


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
            "issuer_authority_id": None,
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
        "issuer_authority_id": rec.get("issuer_authority_id", rec.get("issuer_oracle_id")),
        "last_updated_height": _as_int(rec.get("last_updated_height"), 0),
        "poh_tier_label": poh_tier_label(rec.get("poh_tier")),
    }


def effective_poh_tier(state: Json, account_id: str, *, at_height: int | None = None) -> int:
    rec = canonical_account_poh_status(state, account_id)
    stored_tier = v2_poh_tier(rec.get("poh_tier"))
    status = _as_str(rec.get("status") or POH_STATUS_EXPIRED)

    # Tier-2 expiration never erases the already-earned async verification.
    # Explicit revocation/suspension/challenge remains fail-closed at Tier 0.
    if status == POH_STATUS_EXPIRED:
        return 1 if stored_tier >= 2 else 0
    if status != POH_STATUS_ACTIVE:
        return 0

    expires_at = rec.get("expires_at_height")
    if expires_at is not None:
        try:
            height = _as_int(state.get("height"), 0) if at_height is None else int(at_height)
            if height > int(expires_at):
                return 1 if stored_tier >= 2 else 0
        except Exception:
            return 0
    return stored_tier


def set_account_poh_status(
    state: Json,
    *,
    account_id: str,
    poh_tier: int,
    status: str = POH_STATUS_ACTIVE,
    verified_at_height: int | None = None,
    expires_at_height: int | None = None,
    proof_commitment: str | None = None,
    issuer_authority_id: str | None = None,
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

    height = (
        _as_int(state.get("height"), 0) if last_updated_height is None else int(last_updated_height)
    )
    tier = require_valid_poh_tier(poh_tier)
    # ``issuer_oracle_id`` is accepted only as a read/write-call compatibility
    # alias for older callers.  New canonical records use provider-neutral
    # authority naming and never emit the legacy key.
    issuer_authority_id = (
        issuer_authority_id if issuer_authority_id is not None else issuer_oracle_id
    )
    rec: Json = {
        "account_id": account_id,
        "poh_tier": tier,
        "status": status_norm,
        "verified_at_height": verified_at_height,
        "expires_at_height": expires_at_height,
        "proof_commitment": proof_commitment,
        "issuer_authority_id": issuer_authority_id,
        "last_updated_height": height,
    }
    account_status_root(state)[account_id] = rec

    if mirror_legacy_account_field:
        accounts = state.get("accounts")
        if isinstance(accounts, dict):
            acct = accounts.get(account_id)
            if isinstance(acct, dict):
                # Canonical status is authoritative. Mirrors must reflect exact
                # downgrades as well as upgrades; using max() left expired Tier 2
                # accounts looking Tier 2 to legacy readers.
                acct["poh_tier"] = tier
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
        issuer_authority_id=current.get("issuer_authority_id"),
        last_updated_height=last_updated_height,
    )
    rec["revocation_reason"] = _as_str(reason or "revoked")
    accounts = state.get("accounts")
    if isinstance(accounts, dict) and isinstance(accounts.get(account_id), dict):
        accounts[account_id]["poh_tier"] = 0
        accounts[account_id]["poh_status"] = POH_STATUS_REVOKED
    return rec


def tier2_lifecycle_fields(verified_at_height: int) -> Json:
    verified = int(verified_at_height)
    expires = verified + TIER2_VALIDITY_BLOCKS
    return {
        "verified_at_height": verified,
        "expires_at_height": expires,
        "reverification_open_height": expires - TIER2_REVERIFICATION_WINDOW_BLOCKS,
        "reminder_heights": [expires - offset for offset in TIER2_REMINDER_OFFSETS],
    }


def process_tier2_lifecycle(state: Json, *, next_height: int) -> Json:
    """Apply deterministic Tier-2 reminder, renewal-window, and expiry state.

    This function is idempotent and safe to call in both pre/post scheduler
    phases. It records public receipt-shaped lifecycle entries directly in
    canonical state so every replay schedule reaches the same root.
    """

    height = int(next_height)
    statuses = account_status_root(state)
    poh = poh_root(state)
    lifecycle = poh.get("tier2_lifecycle")
    if not isinstance(lifecycle, dict):
        lifecycle = {}
        poh["tier2_lifecycle"] = lifecycle
    by_account = lifecycle.get("by_account")
    if not isinstance(by_account, dict):
        by_account = {}
        lifecycle["by_account"] = by_account
    receipts = lifecycle.get("receipts")
    if not isinstance(receipts, list):
        receipts = []
        lifecycle["receipts"] = receipts

    reminders = 0
    opened = 0
    expired = 0

    for account_id in sorted(str(key) for key in statuses.keys()):
        rec = statuses.get(account_id)
        if not isinstance(rec, dict):
            continue
        if v2_poh_tier(rec.get("poh_tier")) < 2:
            continue
        verified = rec.get("verified_at_height")
        if verified is None:
            continue
        try:
            fields = tier2_lifecycle_fields(int(verified))
        except Exception:
            continue

        expires_at = rec.get("expires_at_height")
        if expires_at is None:
            expires_at = fields["expires_at_height"]
            rec["expires_at_height"] = expires_at
        else:
            expires_at = int(expires_at)

        item = by_account.get(account_id)
        if not isinstance(item, dict):
            item = {
                "account_id": account_id,
                **fields,
                "status": "active",
                "reminders_emitted": [],
            }
            by_account[account_id] = item
        else:
            item.setdefault("verified_at_height", int(verified))
            item.setdefault("expires_at_height", expires_at)
            item.setdefault(
                "reverification_open_height",
                expires_at - TIER2_REVERIFICATION_WINDOW_BLOCKS,
            )
            item.setdefault(
                "reminder_heights",
                [expires_at - offset for offset in TIER2_REMINDER_OFFSETS],
            )
            if not isinstance(item.get("reminders_emitted"), list):
                item["reminders_emitted"] = []

        emitted = {int(value) for value in item.get("reminders_emitted", [])}
        for reminder_height in item.get("reminder_heights", []):
            reminder_height = int(reminder_height)
            if height == reminder_height and reminder_height not in emitted:
                item["reminders_emitted"].append(reminder_height)
                reminder_receipt = {
                    "receipt_type": "poh_tier2_expiry_reminder",
                    "account_id": account_id,
                    "height": height,
                    "expires_at_height": expires_at,
                }
                receipts.append(reminder_receipt)
                notifications = state.setdefault("notifications", {})
                by_account_notifications = (
                    notifications.setdefault("by_account", {})
                    if isinstance(notifications, dict)
                    else {}
                )
                account_notifications = (
                    by_account_notifications.setdefault(account_id, [])
                    if isinstance(by_account_notifications, dict)
                    else []
                )
                notification_id = f"poh-tier2-reminder:{account_id}:{height}"
                if isinstance(account_notifications, list) and not any(
                    isinstance(value, dict) and value.get("notification_id") == notification_id
                    for value in account_notifications
                ):
                    account_notifications.append(
                        {
                            "notification_id": notification_id,
                            "kind": "poh_tier2_expiry_reminder",
                            "height": height,
                            "expires_at_height": expires_at,
                            "read": False,
                        }
                    )
                reminders += 1

        open_height = int(item.get("reverification_open_height") or 0)
        if height >= open_height and height <= expires_at and not item.get("reverification_opened"):
            item["reverification_opened"] = True
            item["reverification_opened_height"] = open_height
            item["status"] = "reverification_open"
            case_id = f"poh_live:reverify:{account_id}:{expires_at}"
            live_cases = poh.setdefault("live_cases", {})
            if case_id not in live_cases:

                def commitment(
                    label: str,
                    *,
                    bound_case_id: str = case_id,
                    bound_account_id: str = account_id,
                    bound_open_height: int = open_height,
                ) -> str:
                    return hashlib.sha256(
                        (
                            f"{_as_str(state.get('chain_id'))}|{label}|"
                            f"{bound_case_id}|{bound_account_id}|{bound_open_height}"
                        ).encode()
                    ).hexdigest()

                request_commitment = commitment("POH_TIER2_REVERIFY_REQUEST")
                live_cases[case_id] = {
                    "case_id": case_id,
                    "account_id": account_id,
                    "requested_by": "SYSTEM",
                    "status": "requested",
                    "jurors": {},
                    "target_tier": 2,
                    "request_commitment": request_commitment,
                    "requested_height": open_height,
                    "requested_ts_ms": 0,
                    "protocol_native": True,
                    "relay_authority": "transport_only",
                    "reverification": True,
                    "reverification_for_expiry_height": expires_at,
                    "session_commitment": commitment("POH_TIER2_REVERIFY_SESSION"),
                    "room_commitment": commitment("POH_TIER2_REVERIFY_ROOM"),
                    "prompt_commitment": commitment("POH_TIER2_REVERIFY_PROMPT"),
                    "device_pairing_commitment": commitment("POH_TIER2_REVERIFY_DEVICE"),
                }
                session_id = f"session:{case_id}"
                poh.setdefault("live_sessions", {})[session_id] = {
                    "session_id": session_id,
                    "case_id": case_id,
                    "account_id": account_id,
                    "status": "requested",
                    "created_height": open_height,
                    "created_ts_ms": 0,
                    "request_commitment": request_commitment,
                    "relay_authority": "transport_only",
                    "session_commitment": live_cases[case_id]["session_commitment"],
                    "room_commitment": live_cases[case_id]["room_commitment"],
                    "prompt_commitment": live_cases[case_id]["prompt_commitment"],
                    "device_pairing_commitment": live_cases[case_id]["device_pairing_commitment"],
                }
                poh.setdefault("live_session_participants", {}).setdefault(session_id, {})[
                    account_id
                ] = {
                    "role": "subject",
                    "status": "requested",
                    "joined_ts_ms": None,
                    "left_ts_ms": None,
                }
            item["reverification_case_id"] = case_id
            receipts.append(
                {
                    "receipt_type": "poh_tier2_reverification_open",
                    "account_id": account_id,
                    "height": open_height,
                    "processed_height": height,
                    "expires_at_height": expires_at,
                    "case_id": case_id,
                }
            )
            opened += 1

        if height > expires_at and rec.get("status") == POH_STATUS_ACTIVE:
            rec["status"] = POH_STATUS_EXPIRED
            rec["poh_tier"] = 2
            rec["last_updated_height"] = height
            item["status"] = "expired_to_tier1"
            item["expired_height"] = height
            accounts = state.get("accounts")
            if isinstance(accounts, dict) and isinstance(accounts.get(account_id), dict):
                accounts[account_id]["poh_tier"] = 1
                accounts[account_id]["poh_status"] = POH_STATUS_EXPIRED
            responsibilities = mark_tier2_responsibilities_for_replacement(
                state, account_id=account_id, height=height
            )
            receipts.append(
                {
                    "receipt_type": "poh_tier2_expired_to_tier1",
                    "account_id": account_id,
                    "height": height,
                    "expires_at_height": expires_at,
                    "responsibility_replacement_count": len(responsibilities),
                }
            )
            expired += 1

    safe_withdrawals = process_safe_withdrawals(state, next_height=height)
    return {
        "reminders": reminders,
        "reverification_opened": opened,
        "expired": expired,
        "safe_withdrawals": safe_withdrawals,
    }
