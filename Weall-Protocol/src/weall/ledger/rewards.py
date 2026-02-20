# src/weall/ledger/rewards.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from weall.ledger.constants import (
    HALVING_INTERVAL_BLOCKS,
    INITIAL_BLOCK_REWARD,
    MAX_SUPPLY,
    TREASURY_ACCOUNT_ID,
)
from weall.ledger.roles_schema import ensure_roles_schema

Json = Dict[str, Any]


@dataclass
class RewardError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return int(default)


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _ensure_accounts(state: Json) -> Json:
    accts = state.get("accounts")
    if not isinstance(accts, dict):
        accts = {}
        state["accounts"] = accts
    return accts


def _ensure_account(state: Json, account_id: str) -> Json:
    accts = _ensure_accounts(state)
    acct = accts.get(account_id)
    if not isinstance(acct, dict):
        acct = {
            "nonce": 0,
            "poh_tier": 0,
            "banned": False,
            "locked": False,
            "reputation": 0.0,
            "balance": 0,
            "keys": [],
        }
        accts[account_id] = acct
    if "balance" not in acct:
        acct["balance"] = 0
    return acct


def _ensure_economics_root(state: Json) -> Json:
    econ = state.get("economics")
    if not isinstance(econ, dict):
        econ = {}
        state["economics"] = econ
    return econ


def _ensure_monetary_policy(econ: Json) -> Json:
    mp = econ.get("monetary_policy")
    if not isinstance(mp, dict):
        mp = {}
        econ["monetary_policy"] = mp

    mp.setdefault("issued", 0)
    mp.setdefault("max_supply", MAX_SUPPLY)
    mp.setdefault("initial_reward", INITIAL_BLOCK_REWARD)
    mp.setdefault("halving_interval_blocks", HALVING_INTERVAL_BLOCKS)
    mp.setdefault("last_reward_height", 0)

    return mp


def block_subsidy(height: int) -> int:
    """Return the block subsidy (new issuance) for a given block height (1-indexed)."""
    h = int(height)
    if h <= 0:
        return 0
    halvings = h // int(HALVING_INTERVAL_BLOCKS)
    reward = int(INITIAL_BLOCK_REWARD) >> int(halvings)
    return max(int(reward), 0)


def _cap_subsidy_by_remaining_supply(issued: int, subsidy: int) -> Tuple[int, int]:
    issued_i = int(issued)
    sub_i = int(subsidy)
    if issued_i >= MAX_SUPPLY:
        return 0, 0
    remaining = MAX_SUPPLY - issued_i
    if sub_i > remaining:
        sub_i = remaining
    return sub_i, remaining - sub_i


def _uniq_strs(xs: Iterable[Any]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for it in xs:
        s = _as_str(it).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _even_split(amount: int, recipients: List[str]) -> Tuple[Dict[str, int], int]:
    amt = int(amount)
    recips = [r for r in recipients if isinstance(r, str) and r.strip()]
    if amt <= 0 or not recips:
        return {}, amt
    n = len(recips)
    share = amt // n
    if share <= 0:
        return {}, amt
    payouts: Dict[str, int] = {}
    for r in recips:
        payouts[r] = payouts.get(r, 0) + share
    remainder = amt - (share * n)
    return payouts, remainder


def _reward_recipients(state: Json, proposer: str) -> Dict[str, List[str]]:
    roles = ensure_roles_schema(state)

    node_ops = _as_dict(roles.get("node_operators"))
    jurors = _as_dict(roles.get("jurors"))
    creators = _as_dict(roles.get("creators"))

    operators_set = _uniq_strs(_as_list(node_ops.get("active_set")))
    jurors_set = _uniq_strs(_as_list(jurors.get("active_set")))
    creators_set = _uniq_strs(_as_list(creators.get("active_set")))

    prop = str(proposer).strip()
    validators_set = [prop] if prop else []

    return {
        "validators": validators_set,
        "operators": operators_set,
        "jurors": jurors_set,
        "creators": creators_set,
    }


def compute_fee_total_from_receipts(receipts: List[Json]) -> int:
    """Temporary: sum receipts with applied == 'FEE_PAY'."""
    total = 0
    for r in receipts or []:
        if not isinstance(r, dict):
            continue
        if str(r.get("applied", "")).upper() == "FEE_PAY":
            total += _as_int(r.get("amount"), 0)
    return int(max(total, 0))


def apply_genesis_block_rewards(
    state: Json,
    *,
    height: int,
    proposer: str,
    receipts: Optional[List[Json]] = None,
    explicit_fee_total: Optional[int] = None,
) -> Json:
    """Apply Genesis (v2.1) subsidy + fees, split 20/20/20/20/20.

    Treasury receives its 20% bucket plus all remainder from empty buckets
    or integer division.
    """
    if not isinstance(state, dict):
        raise RewardError("invalid_state", "state_not_dict", {"type": str(type(state))})

    h = int(height)
    if h <= 0:
        raise RewardError("invalid_height", "height_must_be_positive", {"height": height})

    econ = _ensure_economics_root(state)
    mp = _ensure_monetary_policy(econ)

    issued = _as_int(mp.get("issued"), 0)
    raw_subsidy = block_subsidy(h)
    subsidy, remaining_after = _cap_subsidy_by_remaining_supply(issued, raw_subsidy)

    if explicit_fee_total is not None:
        fee_total = int(max(int(explicit_fee_total), 0))
    else:
        fee_total = compute_fee_total_from_receipts(receipts or [])

    total_reward = int(subsidy) + int(fee_total)

    # Ensure treasury account exists
    _ensure_account(state, TREASURY_ACCOUNT_ID)

    if total_reward <= 0:
        mp["last_reward_height"] = h
        return {
            "applied": "GENESIS_BLOCK_REWARDS",
            "height": h,
            "proposer": str(proposer),
            "subsidy": int(subsidy),
            "fees": int(fee_total),
            "total": 0,
            "issued_total": int(issued),
            "note": "no_reward",
        }

    per_bucket = total_reward // 5
    buckets = {
        "validators": per_bucket,
        "operators": per_bucket,
        "jurors": per_bucket,
        "creators": per_bucket,
        "treasury": total_reward - (per_bucket * 4),
    }

    recips = _reward_recipients(state, proposer=str(proposer))
    payouts: Dict[str, int] = {}
    treasury_extra = 0

    for bucket_name in ("validators", "operators", "jurors", "creators"):
        amt = int(buckets.get(bucket_name, 0))
        rs = recips.get(bucket_name, [])
        sub_payouts, rem = _even_split(amt, list(rs))
        treasury_extra += int(rem)
        for acct_id, a in sub_payouts.items():
            payouts[acct_id] = payouts.get(acct_id, 0) + int(a)

    payouts[TREASURY_ACCOUNT_ID] = payouts.get(TREASURY_ACCOUNT_ID, 0) + int(buckets.get("treasury", 0)) + int(
        treasury_extra
    )

    for acct_id, amt in payouts.items():
        if amt <= 0:
            continue
        acct = _ensure_account(state, acct_id)
        acct["balance"] = _as_int(acct.get("balance"), 0) + int(amt)

    mp["issued"] = int(issued) + int(subsidy)
    mp["last_reward_height"] = h

    return {
        "applied": "GENESIS_BLOCK_REWARDS",
        "height": h,
        "proposer": str(proposer),
        "subsidy": int(subsidy),
        "fees": int(fee_total),
        "total": int(total_reward),
        "bucket_each": int(per_bucket),
        "treasury_extra": int(treasury_extra),
        "payouts": payouts,
        "issued_total": int(mp["issued"]),
        "remaining_supply_after": int(remaining_after),
    }
