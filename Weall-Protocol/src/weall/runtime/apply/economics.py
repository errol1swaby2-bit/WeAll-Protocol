# src/weall/runtime/apply/economics.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from weall.runtime.econ_phase import deny_if_econ_disabled, deny_if_econ_time_locked
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class EconomicsApplyError(ApplyError):
    """
    Economics domain errors MUST be ApplyError so the executor emits consistent receipts
    (tests assert rejected receipts exist for blocked economic actions before activation).
    """

    code: str
    reason: str
    details: Optional[Json] = None


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _require_system_env(env: TxEnvelope) -> None:
    """
    Economics system actions must be emitted/attributed as SYSTEM context.
    Your executor/system queue typically sets env.system=True and signer=SYSTEM (or system_signer).
    """
    if bool(getattr(env, "system", False)) or _as_str(getattr(env, "signer", "")) == "SYSTEM":
        return
    raise EconomicsApplyError(
        "forbidden",
        "system_tx_required",
        {"tx_type": env.tx_type, "signer": getattr(env, "signer", "")},
    )


def _ensure_params(state: Json) -> Json:
    params = state.get("params")
    if not isinstance(params, dict):
        params = {}
        state["params"] = params
    if "economics_enabled" not in params:
        params["economics_enabled"] = False
    return params


def _ensure_econ_root(state: Json) -> Json:
    econ = state.get("economics")
    if not isinstance(econ, dict):
        econ = {}
        state["economics"] = econ

    econ.setdefault(
        "fee_policy",
        {"transfer_fee_int": 0, "post_fee_int": 0, "comment_fee_int": 0, "like_fee_int": 0},
    )
    econ.setdefault("rate_limit_policy", {})
    econ.setdefault("mempool_reject_receipts", [])
    econ.setdefault("rate_limit_strikes", [])
    econ.setdefault("fee_payments", [])
    return econ


def _wrap_time_lock(state: Json) -> None:
    """
    deny_if_econ_time_locked() raises when now < economic_unlock_time.
    We convert it into an EconomicsApplyError so receipts are consistent.
    """
    try:
        deny_if_econ_time_locked(state)
    except Exception:
        params = _ensure_params(state)
        raise EconomicsApplyError(
            "forbidden",
            "economics_time_locked",
            {"until": _as_int(_as_dict(params).get("economic_unlock_time"), 0)},
        )


def _wrap_disabled(state: Json, tx_type: str) -> None:
    """
    deny_if_econ_disabled() raises if:
      - economics_enabled is false, OR
      - tx_type is blocked by phase rules.
    Convert to EconomicsApplyError for consistent receipts.
    """
    try:
        deny_if_econ_disabled(state, tx_type=tx_type)
    except Exception as e:
        msg = str(e).lower()
        if "time-locked" in msg or "time locked" in msg or "time_locked" in msg:
            raise EconomicsApplyError("forbidden", "economics_time_locked", {"tx_type": tx_type})
        raise EconomicsApplyError("forbidden", "economics_disabled", {"tx_type": tx_type})


def _apply_rate_limit_policy_set(state: Json, env: TxEnvelope) -> Json:
    """
    Canon: RATE_LIMIT_POLICY_SET
    - System tx
    - Anti-spam policy: allowed during Genesis lock (not an economic action)
    """
    _require_system_env(env)
    payload = _as_dict(env.payload)

    econ = _ensure_econ_root(state)
    policy = econ.get("rate_limit_policy")
    if not isinstance(policy, dict):
        policy = {}

    # Merge policy blob deterministically (dict assignment is fine; persisted JSON uses sort_keys=True in executor write)
    for k, v in payload.items():
        policy[str(k)] = v

    econ["rate_limit_policy"] = policy
    return {"applied": "RATE_LIMIT_POLICY_SET"}


def _apply_economics_activation(state: Json, env: TxEnvelope) -> Json:
    """
    Canon: ECONOMICS_ACTIVATION (system/governance controlled)

    - Must be SYSTEM context
    - Must respect the Genesis time-lock (economic_unlock_time)
    - Supports payload toggles: {"enable": bool} or {"enabled": bool}
      (kept for backward compatibility / future governance control)
    - Idempotent: if the requested enabled state is already in effect, reject with a clear reason
      so downstream logic doesn't treat "re-apply" as a meaningful event.
    """
    _require_system_env(env)
    _wrap_time_lock(state)

    params = _ensure_params(state)
    payload = _as_dict(env.payload)

    # Backward compatible toggle keys
    desired = True
    if "enable" in payload:
        desired = _as_bool(payload.get("enable"), True)
    elif "enabled" in payload:
        desired = _as_bool(payload.get("enabled"), True)

    current = bool(params.get("economics_enabled", False))
    if bool(desired) == bool(current):
        raise EconomicsApplyError(
            "invalid_state",
            "economics_already_in_requested_state",
            {"enabled": current},
        )

    params["economics_enabled"] = bool(desired)
    _ensure_econ_root(state)

    return {"applied": "ECONOMICS_ACTIVATION", "enabled": bool(params["economics_enabled"])}


def _apply_fee_policy_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    _wrap_time_lock(state)
    _wrap_disabled(state, "FEE_POLICY_SET")

    payload = _as_dict(env.payload)
    econ = _ensure_econ_root(state)
    fp = econ.get("fee_policy")
    if not isinstance(fp, dict):
        fp = {}

    for k, v in payload.items():
        ks = str(k)
        if ks.endswith("_fee_int"):
            fp[ks] = _as_int(v, 0)
        else:
            fp[ks] = v

    econ["fee_policy"] = fp
    return {"applied": "FEE_POLICY_SET", "fee_policy": fp}


def _apply_fee_pay(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    _wrap_time_lock(state)
    _wrap_disabled(state, "FEE_PAY")

    payload = _as_dict(env.payload)
    econ = _ensure_econ_root(state)

    # Deterministic append order is the order of execution (block tx order).
    econ["fee_payments"].append({"at_nonce": int(env.nonce), "payload": payload, "parent": env.parent})
    return {"applied": "FEE_PAY"}


def _apply_balance_transfer(state: Json, env: TxEnvelope) -> Json:
    _wrap_time_lock(state)
    _wrap_disabled(state, "BALANCE_TRANSFER")

    payload = _as_dict(env.payload)
    to = _as_str(payload.get("to") or payload.get("target") or payload.get("account")).strip()
    amount = payload.get("amount")

    if not to:
        raise EconomicsApplyError("invalid_payload", "missing_to", {"tx_type": env.tx_type})
    if amount is None:
        raise EconomicsApplyError("invalid_payload", "missing_amount", {"tx_type": env.tx_type})

    amt = _as_int(amount, 0)
    if amt <= 0:
        raise EconomicsApplyError("invalid_payload", "bad_amount", {"amount": amount})

    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise EconomicsApplyError("invalid_state", "missing_accounts", {})

    frm = _as_str(env.signer).strip()
    if frm not in accounts:
        raise EconomicsApplyError("not_found", "from_account_missing", {"from": frm})

    if to not in accounts:
        # Create target account if missing (preserving existing behavior)
        accounts[to] = {
            "nonce": 0,
            "poh_tier": 0,
            "banned": False,
            "locked": False,
            "balance": 0,
            "reputation": 0.0,
            "keys": [],
        }

    fa = accounts.get(frm)
    ta = accounts.get(to)
    if not isinstance(fa, dict) or not isinstance(ta, dict):
        raise EconomicsApplyError("invalid_state", "bad_account_shape", {"from": frm, "to": to})

    fb = _as_int(fa.get("balance"), 0)
    tb = _as_int(ta.get("balance"), 0)
    if fb < amt:
        raise EconomicsApplyError("forbidden", "insufficient_funds", {"balance": fb, "amount": amt})

    fa["balance"] = fb - amt
    ta["balance"] = tb + amt

    return {"applied": "BALANCE_TRANSFER", "from": frm, "to": to, "amount": amt}


def _apply_rate_limit_strike_apply(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    econ = _ensure_econ_root(state)

    econ["rate_limit_strikes"].append(
        {
            "at_nonce": int(env.nonce),
            "target": _as_str(payload.get("target") or payload.get("account") or payload.get("account_id")),
            "reason": _as_str(payload.get("reason")),
            "payload": payload,
        }
    )
    return {"applied": "RATE_LIMIT_STRIKE_APPLY"}


def _apply_mempool_reject_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    econ = _ensure_econ_root(state)

    econ["mempool_reject_receipts"].append(
        {
            "at_nonce": int(env.nonce),
            "tx_id": _as_str(payload.get("tx_id")),
            "tx_type": _as_str(payload.get("tx_type")),
            "code": _as_str(payload.get("code")),
            "reason": _as_str(payload.get("reason")),
            "payload": payload,
        }
    )
    return {"applied": "MEMPOOL_REJECT_RECEIPT"}


ECON_TX_TYPES: Set[str] = {
    "RATE_LIMIT_POLICY_SET",
    "ECONOMICS_ACTIVATION",
    "FEE_POLICY_SET",
    "FEE_PAY",
    "BALANCE_TRANSFER",
    "RATE_LIMIT_STRIKE_APPLY",
    "MEMPOOL_REJECT_RECEIPT",
}


def apply_economics(state: Json, env: TxEnvelope) -> Optional[Json]:
    """
    Returns:
      - dict: applied result (debug/receipt convenience)
      - None: tx_type not in economics domain
    """
    t = _as_str(env.tx_type).strip().upper()
    if t not in ECON_TX_TYPES:
        return None

    if t == "RATE_LIMIT_POLICY_SET":
        return _apply_rate_limit_policy_set(state, env)

    if t == "ECONOMICS_ACTIVATION":
        return _apply_economics_activation(state, env)

    if t == "RATE_LIMIT_STRIKE_APPLY":
        return _apply_rate_limit_strike_apply(state, env)

    if t == "MEMPOOL_REJECT_RECEIPT":
        return _apply_mempool_reject_receipt(state, env)

    if t == "FEE_POLICY_SET":
        return _apply_fee_policy_set(state, env)

    if t == "FEE_PAY":
        return _apply_fee_pay(state, env)

    if t == "BALANCE_TRANSFER":
        return _apply_balance_transfer(state, env)

    return None


__all__ = ["EconomicsApplyError", "apply_economics"]
