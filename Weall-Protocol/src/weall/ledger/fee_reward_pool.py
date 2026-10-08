"""Fail-closed identity contract for a protocol-controlled fee reward pool.

This is a validation boundary, not an account provisioning or activation path.
Genesis/migration must create the reserved account with exactly this authority
profile. No ordinary account-registration or user-origin key may own it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from weall.ledger.constants import FEE_REWARD_POOL_ACCOUNT_ID


def validated_fee_reward_pool_balance(state: Mapping[str, Any]) -> int:
    """Return backed existing-supply balance or reject an invalid pool record."""
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise ValueError("fee_reward_pool_missing")
    pool = accounts.get(FEE_REWARD_POOL_ACCOUNT_ID)
    if not isinstance(pool, dict):
        raise ValueError("fee_reward_pool_missing")
    if pool.get("account_type") != "system" or pool.get("system_role") != "fee_reward_pool":
        raise ValueError("fee_reward_pool_not_system_owned")

    # Account signing, recovery, and session authorities cannot coexist with
    # an internal revenue pool. Empty placeholder fields are tolerated.
    for field in ("keys", "recovery", "session_keys", "pubkey", "devices"):
        if pool.get(field):
            raise ValueError("fee_reward_pool_has_user_authority")
    amount = pool.get("balance")
    if type(amount) is not int or amount < 0:
        raise ValueError("fee_reward_pool_invalid_balance")
    return amount
