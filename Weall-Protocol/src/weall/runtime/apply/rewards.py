# src/weall/runtime/apply/rewards.py
from __future__ import annotations

"""
Rewards domain apply semantics.

This module implements deterministic state transitions for:
- block reward mint/distribute
- creator reward allocations
- treasury reward allocations
- forfeiture application
- performance reporting & receipts (canon Performance domain)

It is designed to be deterministic and fail-closed for invalid payloads and
missing preconditions.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class RewardsApplyError(RuntimeError):
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
        return default


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _pick(d: Json, *keys: str) -> Any:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return None


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise RewardsApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_root_list(state: Json, key: str) -> List[Any]:
    cur = state.get(key)
    if not isinstance(cur, list):
        cur = []
        state[key] = cur
    return cur


def _mk_id(prefix: str, env: TxEnvelope, provided: object) -> str:
    s = _as_str(provided).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{env.nonce}"


def _ensure_account(state: Json, account_id: str) -> Json:
    accounts = _ensure_root_dict(state, "accounts")
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        acct = {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "reputation": 0.0, "balance": 0, "keys": []}
        accounts[account_id] = acct
    return acct


def _ensure_rewards(state: Json) -> Json:
    r = _ensure_root_dict(state, "rewards")
    if not isinstance(r.get("reward_pools_by_account"), dict):
        r["reward_pools_by_account"] = {}
    if not isinstance(r.get("block_rewards_by_id"), dict):
        r["block_rewards_by_id"] = {}
    if not isinstance(r.get("creator_allocations_by_id"), dict):
        r["creator_allocations_by_id"] = {}
    if not isinstance(r.get("treasury_allocations_by_id"), dict):
        r["treasury_allocations_by_id"] = {}
    if not isinstance(r.get("forfeitures_by_id"), dict):
        r["forfeitures_by_id"] = {}
    if not isinstance(r.get("stats"), dict):
        r["stats"] = {"minted_total": 0, "distributed_total": 0, "creator_alloc_total": 0, "treasury_alloc_total": 0, "forfeited_total": 0, "last_nonce": 0}
    return r


def _apply_reward_pool_opt_in_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    r = _ensure_rewards(state)

    enabled = payload.get("enabled")
    enabled = True if enabled is None else bool(enabled)

    pools = r["reward_pools_by_account"]
    pools[env.signer] = {"enabled": enabled, "set_at_nonce": int(env.nonce), "payload": payload}
    r["stats"]["last_nonce"] = max(_as_int(r["stats"].get("last_nonce"), 0), int(env.nonce))
    return {"applied": "REWARD_POOL_OPT_IN_SET", "account": env.signer, "enabled": enabled}


def _apply_block_reward_mint(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    r = _ensure_rewards(state)
    payload = _as_dict(env.payload)

    block_id = _pick(payload, "block_id", "id")
    amount = _as_int(payload.get("amount"), 0)
    if not block_id:
        raise RewardsApplyError("invalid_payload", "missing_block_id", {"tx_type": env.tx_type})
    if amount < 0:
        amount = 0

    mints = r["block_rewards_by_id"]
    existing = mints.get(block_id)
    already = isinstance(existing, dict)

    if not already:
        mints[block_id] = {"block_id": block_id, "amount": int(amount), "minted_at_nonce": int(env.nonce), "payload": payload}
        r["stats"]["minted_total"] = _as_int(r["stats"].get("minted_total"), 0) + int(amount)

    r["stats"]["last_nonce"] = max(_as_int(r["stats"].get("last_nonce"), 0), int(env.nonce))
    return {"applied": "BLOCK_REWARD_MINT", "block_id": block_id, "amount": int(amount), "deduped": already}


def _apply_block_reward_distribute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    r = _ensure_rewards(state)
    payload = _as_dict(env.payload)

    block_id = _pick(payload, "block_id", "id")
    if not block_id:
        raise RewardsApplyError("invalid_payload", "missing_block_id", {"tx_type": env.tx_type})

    dists = _ensure_root_dict(state, "reward_distributions_by_block")
    existing = dists.get(block_id)
    already = isinstance(existing, dict)

    distributed_total = 0
    if not already:
        transfers = _as_list(payload.get("transfers"))
        debits = _as_list(payload.get("debits"))

        credited_total, debited_total = _apply_transfers_and_debits(state, payload)
        distributed_total = int(credited_total)

        dists[block_id] = {
            "block_id": block_id,
            "transfers": transfers,
            "debits": debits,
            "distributed_at_nonce": int(env.nonce),
            "payload": payload,
            "credited_total": int(credited_total),
            "debited_total": int(debited_total),
        }
        r["stats"]["distributed_total"] = _as_int(r["stats"].get("distributed_total"), 0) + int(distributed_total)

    r["stats"]["last_nonce"] = max(_as_int(r["stats"].get("last_nonce"), 0), int(env.nonce))
    return {"applied": "BLOCK_REWARD_DISTRIBUTE", "block_id": block_id, "distributed_total": int(distributed_total) if not already else _as_int(existing.get("credited_total"), 0), "deduped": already}


def _apply_transfers_and_debits(state: Json, payload: Json) -> Tuple[int, int]:
    transfers = payload.get("transfers")
    debits = payload.get("debits")
    if not isinstance(transfers, list):
        transfers = []
    if not isinstance(debits, list):
        debits = []

    credited_total = 0
    debited_total = 0

    for tr in transfers:
        if not isinstance(tr, dict):
            continue
        to = tr.get("to") or tr.get("account") or tr.get("account_id")
        amt = _as_int(tr.get("amount"), 0)
        if not isinstance(to, str) or not to:
            continue
        if amt < 0:
            amt = 0
        acct = _ensure_account(state, to)
        acct["balance"] = _as_int(acct.get("balance"), 0) + int(amt)
        credited_total += int(amt)

    for db in debits:
        if not isinstance(db, dict):
            continue
        from_acct = db.get("from") or db.get("account") or db.get("account_id")
        amt = _as_int(db.get("amount"), 0)
        if not isinstance(from_acct, str) or not from_acct:
            continue
        if amt < 0:
            amt = 0
        acct = _ensure_account(state, from_acct)
        bal = _as_int(acct.get("balance"), 0)
        new_bal = bal - int(amt)
        if new_bal < 0:
            new_bal = 0
        acct["balance"] = int(new_bal)
        debited_total += int(amt)

    return int(credited_total), int(debited_total)


def _apply_creator_reward_allocate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    r = _ensure_rewards(state)
    payload = _as_dict(env.payload)

    block_id = _pick(payload, "block_id", "id")
    if not block_id:
        raise RewardsApplyError("invalid_payload", "missing_block_id", {"tx_type": env.tx_type})

    alloc_id = _mk_id("creatoralloc", env, payload.get("alloc_id") or payload.get("id") or block_id)
    allocs = r["creator_allocations_by_id"]
    existing = allocs.get(alloc_id)
    already = isinstance(existing, dict)

    credited_total, debited_total = (0, 0)
    if not already:
        credited_total, debited_total = _apply_transfers_and_debits(state, payload)

        allocs[alloc_id] = {
            "alloc_id": alloc_id,
            "block_id": block_id,
            "transfers": _as_list(payload.get("transfers")),
            "debits": _as_list(payload.get("debits")),
            "at_nonce": int(env.nonce),
            "payload": payload,
            "credited_total": int(credited_total),
            "debited_total": int(debited_total),
        }
        r["stats"]["creator_alloc_total"] = _as_int(r["stats"].get("creator_alloc_total"), 0) + int(credited_total)

    r["stats"]["last_nonce"] = max(_as_int(r["stats"].get("last_nonce"), 0), int(env.nonce))
    return {"applied": "CREATOR_REWARD_ALLOCATE", "alloc_id": alloc_id, "block_id": block_id, "credited_total": int(credited_total) if not already else _as_int(existing.get("credited_total"), 0), "deduped": already}


def _apply_treasury_reward_allocate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    r = _ensure_rewards(state)
    payload = _as_dict(env.payload)

    block_id = _pick(payload, "block_id", "id")
    if not block_id:
        raise RewardsApplyError("invalid_payload", "missing_block_id", {"tx_type": env.tx_type})

    alloc_id = _mk_id("treasuryalloc", env, payload.get("alloc_id") or payload.get("id") or block_id)
    allocs = r["treasury_allocations_by_id"]
    existing = allocs.get(alloc_id)
    already = isinstance(existing, dict)

    credited_total, debited_total = (0, 0)
    if not already:
        credited_total, debited_total = _apply_transfers_and_debits(state, payload)

        allocs[alloc_id] = {
            "alloc_id": alloc_id,
            "block_id": block_id,
            "transfers": _as_list(payload.get("transfers")),
            "debits": _as_list(payload.get("debits")),
            "at_nonce": int(env.nonce),
            "payload": payload,
            "credited_total": int(credited_total),
            "debited_total": int(debited_total),
        }
        r["stats"]["treasury_alloc_total"] = _as_int(r["stats"].get("treasury_alloc_total"), 0) + int(credited_total)

    r["stats"]["last_nonce"] = max(_as_int(r["stats"].get("last_nonce"), 0), int(env.nonce))
    return {"applied": "TREASURY_REWARD_ALLOCATE", "alloc_id": alloc_id, "block_id": block_id, "credited_total": int(credited_total) if not already else _as_int(existing.get("credited_total"), 0), "deduped": already}


def _apply_forfeiture_apply(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    r = _ensure_rewards(state)
    payload = _as_dict(env.payload)

    account_id = _pick(payload, "account_id", "target", "account", "user")
    if not account_id:
        raise RewardsApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    amount = _as_int(payload.get("amount"), 0)
    if amount < 0:
        amount = 0

    forfeit_id = _mk_id("forfeit", env, payload.get("forfeit_id") or payload.get("id"))
    forfeits = r["forfeitures_by_id"]
    existing = forfeits.get(forfeit_id)
    already = isinstance(existing, dict)

    if not already:
        acct = _ensure_account(state, account_id)
        bal = _as_int(acct.get("balance"), 0)
        new_bal = bal - int(amount)
        if new_bal < 0:
            new_bal = 0
        acct["balance"] = int(new_bal)

        forfeits[forfeit_id] = {"forfeit_id": forfeit_id, "account_id": account_id, "amount": int(amount), "at_nonce": int(env.nonce), "payload": payload}
        r["stats"]["forfeited_total"] = _as_int(r["stats"].get("forfeited_total"), 0) + int(amount)

    r["stats"]["last_nonce"] = max(_as_int(r["stats"].get("last_nonce"), 0), int(env.nonce))
    return {"applied": "FORFEITURE_APPLY", "forfeit_id": forfeit_id, "account_id": account_id, "amount": int(amount), "deduped": already}


# ---------------------------------------------------------------------------
# Performance (canon Performance domain)
# ---------------------------------------------------------------------------

def _ensure_performance(state: Json) -> Json:
    perf = state.get("performance")
    if not isinstance(perf, dict):
        perf = {}
        state["performance"] = perf
    if not isinstance(perf.get("reports"), dict):
        perf["reports"] = {}
    if not isinstance(perf.get("evaluations"), list):
        perf["evaluations"] = []
    if not isinstance(perf.get("scores"), list):
        perf["scores"] = []
    return perf


def _apply_performance_report(state: Json, env: TxEnvelope) -> Json:
    """User-context performance reports (mempool)."""
    perf = _ensure_performance(state)
    payload = _as_dict(env.payload)

    report_id = _mk_id("perf", env, payload.get("report_id") or payload.get("id"))
    kind = str(env.tx_type or "").strip()
    subject = _pick(payload, "subject", "account_id", "account", "target")
    subject = subject if isinstance(subject, str) else ""

    if not subject:
        raise RewardsApplyError("invalid_payload", "missing_subject", {"tx_type": kind})

    reports = perf["reports"]
    if report_id in reports:
        return {"applied": kind, "report_id": report_id, "deduped": True}

    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    reports[report_id] = {"report_id": report_id, "kind": kind, "subject": subject, "reported_by": env.signer, "at_nonce": int(env.nonce), "metrics": metrics, "payload": payload}
    return {"applied": kind, "report_id": report_id, "deduped": False}


def _apply_performance_receipt(state: Json, env: TxEnvelope) -> Json:
    """System-context receipts for evaluation and score application."""
    _require_system_env(env)
    perf = _ensure_performance(state)
    payload = _as_dict(env.payload)
    kind = str(env.tx_type or "").strip()

    entry = {"tx_type": kind, "at_nonce": int(env.nonce), "payload": payload}
    if kind == "PERFORMANCE_EVALUATE":
        perf["evaluations"].append(entry)
    else:
        perf["scores"].append(entry)
    return {"applied": kind, "receipt": True}


REWARDS_TX_TYPES: Set[str] = {
    "REWARD_POOL_OPT_IN_SET",
    "BLOCK_REWARD_MINT",
    "BLOCK_REWARD_DISTRIBUTE",
    "CREATOR_REWARD_ALLOCATE",
    "TREASURY_REWARD_ALLOCATE",
    "FORFEITURE_APPLY",
    # Performance
    "CREATOR_PERFORMANCE_REPORT",
    "NODE_OPERATOR_PERFORMANCE_REPORT",
    "PERFORMANCE_EVALUATE",
    "PERFORMANCE_SCORE_APPLY",
}


def apply_rewards(state: Json, env: TxEnvelope) -> Optional[Json]:
    """Apply Rewards txs. Returns meta dict if handled; otherwise None."""
    t = str(env.tx_type or "").strip()
    if t not in REWARDS_TX_TYPES:
        return None

    if t == "REWARD_POOL_OPT_IN_SET":
        return _apply_reward_pool_opt_in_set(state, env)

    if t == "BLOCK_REWARD_MINT":
        return _apply_block_reward_mint(state, env)
    if t == "BLOCK_REWARD_DISTRIBUTE":
        return _apply_block_reward_distribute(state, env)

    if t == "CREATOR_REWARD_ALLOCATE":
        return _apply_creator_reward_allocate(state, env)
    if t == "TREASURY_REWARD_ALLOCATE":
        return _apply_treasury_reward_allocate(state, env)

    if t == "FORFEITURE_APPLY":
        return _apply_forfeiture_apply(state, env)

    if t in {"CREATOR_PERFORMANCE_REPORT", "NODE_OPERATOR_PERFORMANCE_REPORT"}:
        return _apply_performance_report(state, env)

    if t in {"PERFORMANCE_EVALUATE", "PERFORMANCE_SCORE_APPLY"}:
        return _apply_performance_receipt(state, env)

    return None
