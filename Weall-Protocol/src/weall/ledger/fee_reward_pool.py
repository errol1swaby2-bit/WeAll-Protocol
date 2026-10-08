"""Fail-closed identity contract for a protocol-controlled fee reward pool.

This is a validation boundary, not an account provisioning or activation path.
Genesis/migration must create the reserved account with exactly this authority
profile. No ordinary account-registration or user-origin key may own it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from weall.ledger.constants import FEE_REWARD_POOL_ACCOUNT_ID


FEE_REWARD_POOL_CONTRACT_VERSION = 1


def fee_reward_pool_contract_enabled(state: Mapping[str, Any]) -> bool:
    """Only state-committed v1 activation permits restricted pool semantics."""
    params = state.get("params")
    if not isinstance(params, dict):
        return False
    version = params.get("fee_reward_pool_contract_version")
    return (
        type(version) is int
        and version == FEE_REWARD_POOL_CONTRACT_VERSION
        and params.get("fee_sink_account") == FEE_REWARD_POOL_ACCOUNT_ID
    )


def new_fee_reward_pool_genesis_account() -> dict[str, Any]:
    """Return a deterministic, unkeyed system account for *fresh* genesis."""
    return {
        "account_type": "system",
        "system_role": "fee_reward_pool",
        "balance": 0,
    }


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

    # Strict minimal shape: extra key/recovery/nonce/session fields are not
    # tolerated, even when initially empty. They could become user authority.
    if set(pool) != {"account_type", "system_role", "balance"}:
        raise ValueError("fee_reward_pool_has_user_authority")
    amount = pool.get("balance")
    if type(amount) is not int or amount < 0:
        raise ValueError("fee_reward_pool_invalid_balance")
    return amount
