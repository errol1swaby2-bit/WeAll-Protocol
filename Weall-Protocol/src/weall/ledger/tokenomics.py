from __future__ import annotations

from typing import Any

from weall.ledger import constants as ledger_constants
from weall.ledger.issuance import (
    cap_issuance_by_remaining_supply,
    epoch_issuance_subsidy_atomic,
    issuance_due_at_height,
    issuance_epoch_index_for_due_height,
    issuance_epoch_index_for_height,
    issuance_height_for_epoch,
    issuance_subsidy_for_height,
    next_halving_issuance_epoch,
    next_issuance_height_after_height,
)
from weall.runtime.econ_phase import econ_allowed_from_state, is_econ_unlocked

Json = dict[str, Any]

COIN = int(getattr(ledger_constants, "COIN", 100_000_000))
COIN_DECIMALS = int(getattr(ledger_constants, "COIN_DECIMALS", 8))
MAX_SUPPLY_WCN = int(getattr(ledger_constants, "MAX_SUPPLY_WCN", 21_000_000))
MAX_SUPPLY = int(getattr(ledger_constants, "MAX_SUPPLY", MAX_SUPPLY_WCN * COIN))
TARGET_BLOCK_INTERVAL_SECONDS = int(getattr(ledger_constants, "TARGET_BLOCK_INTERVAL_SECONDS", 20))
ISSUANCE_EPOCH_SECONDS = int(getattr(ledger_constants, "ISSUANCE_EPOCH_SECONDS", 600))
ISSUANCE_EPOCH_BLOCKS = int(getattr(ledger_constants, "ISSUANCE_EPOCH_BLOCKS", 30))
INITIAL_ISSUANCE_PER_EPOCH_WCN = int(getattr(ledger_constants, "INITIAL_ISSUANCE_PER_EPOCH_WCN", 100))
INITIAL_ISSUANCE_PER_EPOCH = int(
    getattr(ledger_constants, "INITIAL_ISSUANCE_PER_EPOCH", INITIAL_ISSUANCE_PER_EPOCH_WCN * COIN)
)
HALVING_INTERVAL_ISSUANCE_EPOCHS = int(
    getattr(ledger_constants, "HALVING_INTERVAL_ISSUANCE_EPOCHS", 105_120)
)
HALVING_INTERVAL_BLOCKS = int(
    getattr(ledger_constants, "HALVING_INTERVAL_BLOCKS", HALVING_INTERVAL_ISSUANCE_EPOCHS * ISSUANCE_EPOCH_BLOCKS)
)

# Compatibility aliases for older callers.  The values now point to the v1.5
# epoch issuance schedule, not a per-block mint schedule.
TARGET_BLOCK_TIME_SECONDS = TARGET_BLOCK_INTERVAL_SECONDS
INITIAL_BLOCK_REWARD_WCN = INITIAL_ISSUANCE_PER_EPOCH_WCN
INITIAL_BLOCK_REWARD = INITIAL_ISSUANCE_PER_EPOCH

REWARD_BUCKETS = tuple(
    getattr(
        ledger_constants,
        "REWARD_BUCKETS",
        ("validators", "operators", "jurors", "creators", "treasury"),
    )
)

REWARD_BUCKET_BPS: dict[str, int] = {
    "validators": 2_000,
    "operators": 2_000,
    "jurors": 2_000,
    "creators": 2_000,
    "treasury": 2_000,
}

FEE_FREE_ACTION_CLASSES: tuple[str, ...] = (
    "account_onboarding",
    "proof_of_humanity",
    "posting",
    "comments",
    "reactions",
    "group_participation",
    "governance_proposals",
    "governance_votes",
    "reports",
    "reviews",
    "appeals",
    "observer_onboarding",
    "peer_onboarding",
)

ECONOMIC_ACTION_CLASSES: tuple[str, ...] = (
    "balance_transfer",
    "fee_payment",
    "epoch_issuance_mint",
    "epoch_issuance_distribution",
    "creator_reward_allocation",
    "treasury_reward_allocation",
    "treasury_spend",
    "group_treasury_spend",
)


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def block_subsidy_atomic(height: int) -> int:
    """Compatibility wrapper: return issuance only at epoch boundary heights."""

    return int(issuance_subsidy_for_height(int(height)))


def next_halving_height(height: int) -> int:
    """Compatibility wrapper returning the block height of the next halving boundary."""

    current_epoch = max(0, issuance_epoch_index_for_height(int(height)))
    return issuance_height_for_epoch(next_halving_issuance_epoch(current_epoch))


def _balances_total_atomic(state: Json) -> int:
    total = 0
    accounts = _as_dict(state.get("accounts"))
    for account in accounts.values():
        if isinstance(account, dict):
            total += max(0, _as_int(account.get("balance"), 0))
    return int(total)


def tokenomics_policy_from_state(state: Json) -> Json:
    """Return the canonical WeCoin/tokenomics policy read model.

    This function is read-only. It does not activate economics, mint rewards,
    move balances, or mutate treasury state. Apply modules remain the authority
    for state transitions.
    """

    st = state if isinstance(state, dict) else {}
    params = _as_dict(st.get("params"))
    economics = _as_dict(st.get("economics"))
    monetary_policy = _as_dict(economics.get("monetary_policy"))

    height = _as_int(st.get("height"), 0)
    issued = _as_int(monetary_policy.get("issued"), 0)
    circulating = _balances_total_atomic(st)

    try:
        unlocked = bool(is_econ_unlocked(st))
    except Exception:
        unlocked = False

    try:
        enabled = bool(econ_allowed_from_state(st))
    except Exception:
        enabled = False

    remaining_supply = max(0, int(MAX_SUPPLY) - int(issued))
    current_epoch = issuance_epoch_index_for_height(height)
    next_issuance_height = next_issuance_height_after_height(height)
    next_epoch = issuance_epoch_index_for_due_height(next_issuance_height)
    raw_next_epoch_issuance = epoch_issuance_subsidy_atomic(next_epoch)
    capped_next_epoch_issuance, remaining_after_next = cap_issuance_by_remaining_supply(
        issued, raw_next_epoch_issuance, max_supply=MAX_SUPPLY
    )
    next_halving_epoch = next_halving_issuance_epoch(max(0, current_epoch))

    return {
        "ok": True,
        "name": "WeCoin",
        "symbol": "WCN",
        "precision": {
            "decimals": int(COIN_DECIMALS),
            "atomic_units_per_coin": int(COIN),
        },
        "supply": {
            "max_supply_wcn": int(MAX_SUPPLY_WCN),
            "max_supply_atomic": int(MAX_SUPPLY),
            "issued_atomic": int(issued),
            "remaining_issuance_atomic": int(remaining_supply),
            "remaining_after_next_epoch_issuance_atomic": int(remaining_after_next),
            "circulating_account_balances_atomic": int(circulating),
            "premine_atomic": int(circulating) if height == 0 else None,
        },
        "emission": {
            "issuance_model": "epoch_based",
            "per_block_issuance": False,
            "target_block_interval_seconds": int(TARGET_BLOCK_INTERVAL_SECONDS),
            "issuance_epoch_seconds": int(ISSUANCE_EPOCH_SECONDS),
            "issuance_epoch_blocks": int(ISSUANCE_EPOCH_BLOCKS),
            "initial_epoch_issuance_wcn": int(INITIAL_ISSUANCE_PER_EPOCH_WCN),
            "initial_epoch_issuance_atomic": int(INITIAL_ISSUANCE_PER_EPOCH),
            "halving_interval_issuance_epochs": int(HALVING_INTERVAL_ISSUANCE_EPOCHS),
            "halving_interval_blocks_at_target": int(HALVING_INTERVAL_BLOCKS),
            "current_height": int(height),
            "current_issuance_epoch": int(current_epoch),
            "height_is_issuance_boundary": bool(issuance_due_at_height(height)),
            "next_issuance_height": int(next_issuance_height),
            "next_issuance_epoch": int(next_epoch),
            "next_epoch_issuance_atomic": int(capped_next_epoch_issuance),
            "raw_next_epoch_issuance_atomic": int(raw_next_epoch_issuance),
            "next_halving_issuance_epoch": int(next_halving_epoch),
            "next_halving_height_at_target": int(issuance_height_for_epoch(next_halving_epoch)),
            "supply_cap_enforced": True,
            "duplicate_epoch_issuance_invalid": True,
        },
        "reward_split": {
            "basis_points": dict(REWARD_BUCKET_BPS),
            "buckets": list(REWARD_BUCKETS),
            "equal_20_percent_buckets": True,
            "locked_with_economics": not bool(enabled),
        },
        "activation": {
            "unlocked": bool(unlocked),
            "enabled": bool(enabled),
            "locked": not bool(enabled),
            "economic_unlock_time": _as_int(params.get("economic_unlock_time"), 0),
            "economic_unlock_height": _as_int(params.get("economic_unlock_height"), 0),
            "requires_governance_activation": True,
            "activation_tx_type": "ECONOMICS_ACTIVATION",
        },
        "fee_free_action_classes": list(FEE_FREE_ACTION_CLASSES),
        "economic_action_classes": list(ECONOMIC_ACTION_CLASSES),
        "truth_label": "real_tokenomics_locked" if not enabled else "real_tokenomics_active",
        "claim": (
            "WeCoin tokenomics are epoch-based and supply-capped. Issuance occurs "
            "once per 10-minute issuance epoch, equal to 30 blocks at the 20-second "
            "target interval, and stops at the 21,000,000 WCN cap. Transfers, rewards, "
            "fees, and treasury spends remain locked until the Genesis economic lock "
            "and governance activation path are satisfied. Civic, social, PoH, review, "
            "and governance participation remain fee-free."
        ),
    }


__all__ = [
    "COIN",
    "COIN_DECIMALS",
    "ECONOMIC_ACTION_CLASSES",
    "FEE_FREE_ACTION_CLASSES",
    "HALVING_INTERVAL_BLOCKS",
    "HALVING_INTERVAL_ISSUANCE_EPOCHS",
    "INITIAL_BLOCK_REWARD",
    "INITIAL_BLOCK_REWARD_WCN",
    "INITIAL_ISSUANCE_PER_EPOCH",
    "INITIAL_ISSUANCE_PER_EPOCH_WCN",
    "ISSUANCE_EPOCH_BLOCKS",
    "ISSUANCE_EPOCH_SECONDS",
    "MAX_SUPPLY",
    "MAX_SUPPLY_WCN",
    "REWARD_BUCKET_BPS",
    "TARGET_BLOCK_INTERVAL_SECONDS",
    "TARGET_BLOCK_TIME_SECONDS",
    "block_subsidy_atomic",
    "cap_issuance_by_remaining_supply",
    "epoch_issuance_subsidy_atomic",
    "issuance_due_at_height",
    "issuance_epoch_index_for_due_height",
    "issuance_epoch_index_for_height",
    "issuance_height_for_epoch",
    "issuance_subsidy_for_height",
    "next_halving_height",
    "next_halving_issuance_epoch",
    "next_issuance_height_after_height",
    "tokenomics_policy_from_state",
]
