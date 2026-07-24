from __future__ import annotations

"""Consensus-visible account-recovery policy helpers.

This module centralizes the post-recovery restriction boundary so mempool gate
checks and apply-time defense-in-depth enforce the same rule.  It is deliberately
pure: no wall clock, environment, network, or provider lookups are permitted.
"""

from typing import Any

Json = dict[str, Any]

RECOVERY_RESTRICTION_BLOCKS = 8_640
RECOVERY_REQUEST_COOLDOWN_BLOCKS = 4_320
RECOVERY_FAILED_WINDOW_BLOCKS = 129_600
RECOVERY_MAX_FAILED_ATTEMPTS = 3

# During the bounded recovery restriction, only low-risk security and social
# controls remain available.  Read access is outside transaction admission.
RECOVERY_RESTRICTION_ALLOWED_TX_TYPES: frozenset[str] = frozenset(
    {
        "ACCOUNT_KEY_ADD",
        "ACCOUNT_KEY_REVOKE",
        "ACCOUNT_DEVICE_REGISTER",
        "ACCOUNT_DEVICE_REVOKE",
        "ACCOUNT_SESSION_KEY_ISSUE",
        "ACCOUNT_SESSION_KEY_REVOKE",
        "ACCOUNT_SECURITY_POLICY_SET",
        "ACCOUNT_RECOVERY_CONFIG_SET",
        "ACCOUNT_RECOVERY_REQUEST",
        "ACCOUNT_RECOVERY_APPROVE",
        "FOLLOW_SET",
        "BLOCK_SET",
        "MUTE_SET",
        "CONTENT_REACTION_SET",
        "NOTIFICATION_SUBSCRIBE",
        "NOTIFICATION_UNSUBSCRIBE",
    }
)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _account_record(state: Json, account_id: str) -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return {}
    rec = accounts.get(str(account_id or "").strip())
    return rec if isinstance(rec, dict) else {}


def recovery_restriction_until_height(state: Json, account_id: str) -> int:
    account = _account_record(state, account_id)
    recovery = account.get("recovery")
    if not isinstance(recovery, dict):
        return 0
    return max(0, _as_int(recovery.get("restriction_until_height"), 0))


def recovery_restriction_active(
    state: Json,
    account_id: str,
    *,
    at_height: int | None = None,
) -> bool:
    height = _as_int(state.get("height"), 0) + 1 if at_height is None else int(at_height)
    return height <= recovery_restriction_until_height(state, account_id)


def recovery_restriction_allows_tx(
    state: Json,
    account_id: str,
    tx_type: str,
    *,
    at_height: int | None = None,
) -> bool:
    if not recovery_restriction_active(state, account_id, at_height=at_height):
        return True
    return str(tx_type or "").strip().upper() in RECOVERY_RESTRICTION_ALLOWED_TX_TYPES


__all__ = [
    "RECOVERY_FAILED_WINDOW_BLOCKS",
    "RECOVERY_MAX_FAILED_ATTEMPTS",
    "RECOVERY_REQUEST_COOLDOWN_BLOCKS",
    "RECOVERY_RESTRICTION_ALLOWED_TX_TYPES",
    "RECOVERY_RESTRICTION_BLOCKS",
    "recovery_restriction_active",
    "recovery_restriction_allows_tx",
    "recovery_restriction_until_height",
]
