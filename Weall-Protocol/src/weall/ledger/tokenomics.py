# src/weall/ledger/tokenomics.py
from __future__ import annotations

from typing import Any

from weall.ledger import constants as ledger_constants
from weall.runtime.econ_phase import econ_allowed_from_state, is_econ_unlocked

Json = dict[str, Any]

COIN = int(getattr(ledger_constants, "COIN", 100_000_000))
COIN_DECIMALS = int(getattr(ledger_constants, "COIN_DECIMALS", 8))
MAX_SUPPLY_WCN = int(getattr(ledger_constants, "MAX_SUPPLY_WCN", 21_000_000))
MAX_SUPPLY = int(getattr(ledger_constants, "MAX_SUPPLY", MAX_SUPPLY_WCN * COIN))
INITIAL_BLOCK_REWARD_WCN = int(getattr(ledger_constants, "INITIAL_BLOCK_REWARD_WCN", 100))
INITIAL_BLOCK_REWARD = int(getattr(ledger_constants, "INITIAL_BLOCK_REWARD", INITIAL_BLOCK_REWARD_WCN * COIN))
HALVING_INTERVAL_BLOCKS = int(getattr(ledger_constants, "HALVING_INTERVAL_BLOCKS", 105_120))
TARGET_BLOCK_TIME_SECONDS = int(getattr(ledger_constants, "TARGET_BLOCK_TIME_SECONDS", 600))

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
    "block_reward_mint",
    "block_reward_distribution",
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
    """Return deterministic block subsidy in atomic WeCoin units.

    Height is treated as the reward-bearing block height. Height 0 receives no
    subsidy. Height 1 begins the initial subsidy schedule.
    """

    h = int(height)
    if h <= 0:
        return 0

    halvings = h // int(HALVING_INTERVAL_BLOCKS)
    subsidy = int(INITIAL_BLOCK_REWARD) >> int(halvings)
    return max(int(subsidy), 0)


def next_halving_height(height: int) -> int:
    h = max(0, int(height))
    current_epoch = h // int(HALVING_INTERVAL_BLOCKS)
    return int((current_epoch + 1) * int(HALVING_INTERVAL_BLOCKS))


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

    raw_next_subsidy = block_subsidy_atomic(max(1, height + 1))
    remaining_supply = max(0, int(MAX_SUPPLY) - int(issued))
    capped_next_subsidy = min(int(raw_next_subsidy), int(remaining_supply))

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
            "circulating_account_balances_atomic": int(circulating),
            "premine_atomic": int(circulating) if height == 0 else None,
        },
        "emission": {
            "target_block_time_seconds": int(TARGET_BLOCK_TIME_SECONDS),
            "initial_block_reward_wcn": int(INITIAL_BLOCK_REWARD_WCN),
            "initial_block_reward_atomic": int(INITIAL_BLOCK_REWARD),
            "halving_interval_blocks": int(HALVING_INTERVAL_BLOCKS),
            "current_height": int(height),
            "next_reward_height": int(height + 1),
            "next_block_subsidy_atomic": int(capped_next_subsidy),
            "raw_next_block_subsidy_atomic": int(raw_next_subsidy),
            "next_halving_height": int(next_halving_height(height)),
            "supply_cap_enforced": True,
        },
        "reward_split": {
            "basis_points": dict(REWARD_BUCKET_BPS),
            "buckets": list(REWARD_BUCKETS),
            "equal_20_percent_buckets": True,
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
            "WeCoin tokenomics are defined and supply-capped. Transfers, rewards, "
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
    "INITIAL_BLOCK_REWARD",
    "INITIAL_BLOCK_REWARD_WCN",
    "MAX_SUPPLY",
    "MAX_SUPPLY_WCN",
    "REWARD_BUCKET_BPS",
    "TARGET_BLOCK_TIME_SECONDS",
    "block_subsidy_atomic",
    "next_halving_height",
    "tokenomics_policy_from_state",
]
