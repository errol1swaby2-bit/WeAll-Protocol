# src/weall/runtime/apply/economics.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.runtime.econ_phase import deny_if_econ_disabled, deny_if_econ_time_locked
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


@dataclass
class EconomicsApplyError(ApplyError):
    """
    Economics domain errors MUST be ApplyError so the executor emits consistent receipts
    (tests assert rejected receipts exist for blocked economic actions before activation).
    """

    code: str
    reason: str
    details: Json | None = None


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


def _accounts_root(state: Json) -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise EconomicsApplyError("invalid_state", "missing_accounts", {})
    return accounts


def _require_existing_account(state: Json, account_id: str, *, field: str) -> Json:
    account = _accounts_root(state).get(account_id)
    if not isinstance(account, dict):
        raise EconomicsApplyError(
            "not_found",
            f"{field}_account_missing",
            {field: account_id},
        )
    return account


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



_RATE_LIMIT_MIN_WINDOW_MS = 1_000
_RATE_LIMIT_MAX_WINDOW_MS = 86_400_000
_RATE_LIMIT_MIN_LIMIT = 1
_RATE_LIMIT_MAX_LIMIT = 1_000_000
_RATE_LIMIT_PROTECTED_MIN_PER_HOUR = 10

_RATE_LIMIT_SCOPE_ALIASES = {
    "": "global",
    "default": "global",
    "all": "global",
    "global": "global",
    "read": "read",
    "reads": "read",
    "write": "write",
    "writes": "write",
    "tx": "tx_submit",
    "tx_submit": "tx_submit",
    "mempool": "mempool",
    "relay": "relay",
    "state_sync": "state_sync",
    "bft": "bft",
    "helper": "helper",
    "media": "media_upload",
    "media_upload": "media_upload",
    "account": "account_onboarding",
    "account_register": "account_onboarding",
    "account_registration": "account_onboarding",
    "account_onboarding": "account_onboarding",
    "onboarding": "account_onboarding",
    "poh": "poh_onboarding",
    "poh_async": "poh_onboarding",
    "poh_live": "poh_onboarding",
    "poh_onboarding": "poh_onboarding",
    "peer": "peer_onboarding",
    "peers": "peer_onboarding",
    "peer_advertise": "peer_onboarding",
    "peer_request_connect": "peer_onboarding",
    "rendezvous": "peer_onboarding",
    "peer_onboarding": "peer_onboarding",
    "observer": "observer_onboarding",
    "observer_onboarding": "observer_onboarding",
    "node_registration": "observer_onboarding",
}

_RATE_LIMIT_PROTECTED_SCOPES = frozenset(
    {"account_onboarding", "poh_onboarding", "peer_onboarding", "observer_onboarding"}
)


def _canonical_rate_limit_scope(raw: Any) -> str:
    key = _as_str(raw).strip().lower().replace("-", "_").replace("/", "_")
    if key not in _RATE_LIMIT_SCOPE_ALIASES:
        raise EconomicsApplyError("forbidden", "rate_limit_scope_not_allowed", {"scope": raw})
    return _RATE_LIMIT_SCOPE_ALIASES[key]


def _bounded_rate_limit_int(raw: Any, *, field: str, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except Exception as exc:
        raise EconomicsApplyError("invalid_payload", f"bad_rate_limit_{field}", {field: raw}) from exc
    if value < int(minimum) or value > int(maximum):
        raise EconomicsApplyError(
            "forbidden",
            f"rate_limit_{field}_out_of_bounds",
            {"field": field, "value": value, "min": int(minimum), "max": int(maximum)},
        )
    return value


def _validate_rate_limit_rule(scope: str, rule: Json) -> Json:
    if not isinstance(rule, dict):
        raise EconomicsApplyError("invalid_payload", "rate_limit_rule_must_be_object", {"scope": scope})

    extras = sorted(
        str(k)
        for k in rule.keys()
        if str(k) not in {"scope", "window_ms", "limit", "burst", "rate_per_sec", "note"}
    )
    if extras:
        raise EconomicsApplyError(
            "forbidden", "rate_limit_rule_field_not_allowed", {"scope": scope, "fields": extras}
        )

    window_ms = _bounded_rate_limit_int(
        rule.get("window_ms", _RATE_LIMIT_MIN_WINDOW_MS),
        field="window_ms",
        minimum=_RATE_LIMIT_MIN_WINDOW_MS,
        maximum=_RATE_LIMIT_MAX_WINDOW_MS,
    )
    limit = _bounded_rate_limit_int(
        rule.get("limit", rule.get("burst", rule.get("rate_per_sec", _RATE_LIMIT_MIN_LIMIT))),
        field="limit",
        minimum=_RATE_LIMIT_MIN_LIMIT,
        maximum=_RATE_LIMIT_MAX_LIMIT,
    )

    if scope in _RATE_LIMIT_PROTECTED_SCOPES:
        per_hour = (int(limit) * 3_600_000) // max(1, int(window_ms))
        if per_hour < _RATE_LIMIT_PROTECTED_MIN_PER_HOUR:
            raise EconomicsApplyError(
                "forbidden",
                "rate_limit_protected_onboarding_scope_too_restrictive",
                {
                    "scope": scope,
                    "limit": int(limit),
                    "window_ms": int(window_ms),
                    "min_per_hour": _RATE_LIMIT_PROTECTED_MIN_PER_HOUR,
                },
            )

    out = {"window_ms": int(window_ms), "limit": int(limit)}
    if "note" in rule:
        out["note"] = _as_str(rule.get("note"))[:160]
    return out


def _normalize_rate_limit_policy_payload(payload: Json) -> Json:
    allowed_top = {"scope", "window_ms", "limit", "policy"}
    extras = sorted(str(k) for k in payload.keys() if str(k) not in allowed_top)
    if extras:
        raise EconomicsApplyError("forbidden", "rate_limit_policy_field_not_allowed", {"fields": extras})

    rules: dict[str, Json] = {}

    if any(k in payload for k in ("scope", "window_ms", "limit")):
        scope = _canonical_rate_limit_scope(payload.get("scope", "global"))
        rules[scope] = _validate_rate_limit_rule(
            scope,
            {
                "window_ms": payload.get("window_ms", _RATE_LIMIT_MIN_WINDOW_MS),
                "limit": payload.get("limit", _RATE_LIMIT_MIN_LIMIT),
            },
        )

    nested = payload.get("policy")
    if nested is not None:
        if not isinstance(nested, dict):
            raise EconomicsApplyError("invalid_payload", "rate_limit_policy_must_be_object", {})
        if any(k in nested for k in ("scope", "window_ms", "limit")):
            scope = _canonical_rate_limit_scope(nested.get("scope", "global"))
            rules[scope] = _validate_rate_limit_rule(scope, nested)
        else:
            for raw_scope, raw_rule in nested.items():
                scope = _canonical_rate_limit_scope(raw_scope)
                if not isinstance(raw_rule, dict):
                    raise EconomicsApplyError(
                        "invalid_payload", "rate_limit_rule_must_be_object", {"scope": raw_scope}
                    )
                rule = dict(raw_rule)
                rule.setdefault("scope", scope)
                rules[scope] = _validate_rate_limit_rule(scope, rule)

    if not rules:
        raise EconomicsApplyError("invalid_payload", "empty_rate_limit_policy", {})

    return {"version": 1, "rules": {k: rules[k] for k in sorted(rules)}}


def _apply_rate_limit_policy_set(state: Json, env: TxEnvelope) -> Json:
    """
    Canon: RATE_LIMIT_POLICY_SET
    - System tx
    - Governance/system-controlled anti-spam policy: allowed during Genesis lock
      because it is not an economics activation path.
    - Fails closed on arbitrary blobs so rate limits cannot become a hidden
      capture surface for onboarding, PoH, peer, or observer participation.
    """
    _require_system_env(env)
    payload = _as_dict(env.payload)
    normalized = _normalize_rate_limit_policy_payload(payload)

    econ = _ensure_econ_root(state)
    econ["rate_limit_policy"] = normalized
    return {"applied": "RATE_LIMIT_POLICY_SET", "rate_limit_policy": normalized}


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


_CIVIC_FEE_KEYS = frozenset(
    {
        # Civic/social/governance anti-spam must remain PoH/rate-limit based,
        # not fee-gated.  These legacy keys may remain in genesis/state at zero
        # for compatibility, but governance may not set them positive.
        "post_fee_int",
        "comment_fee_int",
        "like_fee_int",
        "reaction_fee_int",
        "share_fee_int",
        "follow_fee_int",
        "group_fee_int",
        "group_join_fee_int",
        "governance_fee_int",
        "governance_vote_fee_int",
        "governance_proposal_fee_int",
        "proposal_fee_int",
        "vote_fee_int",
        "poh_fee_int",
        "poh_request_fee_int",
        "dispute_fee_int",
        "dispute_open_fee_int",
        "review_fee_int",
        "onboarding_fee_int",
        "account_register_fee_int",
        "peer_advertise_fee_int",
    }
)


def _reject_civic_fee_gate(payload: Json) -> None:
    for k, v in payload.items():
        ks = str(k)
        if ks in _CIVIC_FEE_KEYS and _as_int(v, 0) > 0:
            raise EconomicsApplyError(
                "forbidden",
                "civic_social_governance_actions_must_remain_fee_free",
                {"field": ks, "value": v},
            )
        if ks == "policy" and isinstance(v, dict):
            _reject_civic_fee_gate(v)


def _apply_fee_policy_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    _wrap_time_lock(state)
    _wrap_disabled(state, "FEE_POLICY_SET")

    payload = _as_dict(env.payload)
    _reject_civic_fee_gate(payload)
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
    """Apply a user-origin fee payment after economics activation.

    Canon marks FEE_PAY as USER/mempool/Tier0+.  This function therefore must
    not require SYSTEM context.  When ``amount`` is positive, the signer (or
    explicit from_account_id, which must equal the signer) is debited and an
    optional fee sink account is credited.  Zero-amount records are allowed for
    compatibility with older accounting receipts but never mint value.
    """

    _wrap_time_lock(state)
    _wrap_disabled(state, "FEE_PAY")

    payload = _as_dict(env.payload)
    econ = _ensure_econ_root(state)
    signer = _as_str(env.signer).strip()
    from_account = _as_str(payload.get("from_account_id") or payload.get("from") or signer).strip()
    if from_account and signer and from_account != signer:
        raise EconomicsApplyError(
            "forbidden",
            "fee_pay_signer_mismatch",
            {"signer": signer, "from_account_id": from_account},
        )
    if not from_account:
        raise EconomicsApplyError("invalid_payload", "missing_from_account", {"tx_type": env.tx_type})

    amount = _as_int(payload.get("amount"), 0)
    if amount < 0:
        raise EconomicsApplyError("invalid_payload", "bad_amount", {"amount": payload.get("amount")})

    to_account = _as_str(
        payload.get("to_account_id")
        or payload.get("to")
        or payload.get("target")
        or _as_dict(state.get("params")).get("fee_sink_account")
        or ""
    ).strip()

    if amount > 0:
        payer = _require_existing_account(state, from_account, field="from")
        balance = _as_int(payer.get("balance"), 0)
        if balance < amount:
            raise EconomicsApplyError(
                "forbidden", "insufficient_funds", {"balance": balance, "amount": amount}
            )
        sink = None
        if to_account:
            sink = _require_existing_account(state, to_account, field="to")
        payer["balance"] = balance - amount
        if sink is not None:
            sink["balance"] = _as_int(sink.get("balance"), 0) + amount

    payment = {
        "at_nonce": int(env.nonce),
        "from": from_account,
        "to": to_account,
        "amount": int(amount),
        "tx_id": _as_str(payload.get("tx_id")),
        "tx_type": _as_str(payload.get("tx_type")),
        "payload": payload,
        "parent": env.parent,
    }
    econ["fee_payments"].append(payment)
    return {"applied": "FEE_PAY", "from": from_account, "to": to_account, "amount": int(amount)}


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

    frm = _as_str(env.signer).strip()
    fa = _require_existing_account(state, frm, field="from")
    ta = _require_existing_account(state, to, field="to")

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
    target = _as_str(payload.get("target") or payload.get("account") or payload.get("account_id")).strip()
    if not target:
        raise EconomicsApplyError("invalid_payload", "missing_rate_limit_strike_target", {})
    _require_existing_account(state, target, field="target")

    econ["rate_limit_strikes"].append(
        {
            "at_nonce": int(env.nonce),
            "target": target,
            "reason": _as_str(payload.get("reason")),
            "payload": payload,
        }
    )
    return {"applied": "RATE_LIMIT_STRIKE_APPLY", "target": target}


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


ECON_TX_TYPES: set[str] = {
    "RATE_LIMIT_POLICY_SET",
    "ECONOMICS_ACTIVATION",
    "FEE_POLICY_SET",
    "FEE_PAY",
    "BALANCE_TRANSFER",
    "RATE_LIMIT_STRIKE_APPLY",
    "MEMPOOL_REJECT_RECEIPT",
}


def apply_economics(state: Json, env: TxEnvelope) -> Json | None:
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
