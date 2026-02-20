# src/weall/runtime/apply/reputation.py
from __future__ import annotations

"""Reputation domain apply semantics.

Production posture:
- Reputation is a hard protocol constant clamped to [-100, 100]
- Hitting -100 auto-bans the account (accounts[acct]["banned"] = True)
- Governance does NOT adjust thresholds; it may only reinstate via canon receipts

Canon Reputation txs (receipt-only, SYSTEM):
- REPUTATION_DELTA_APPLY (parent=DISPUTE_RESOLVE)
- REPUTATION_THRESHOLD_CROSS (parent=REPUTATION_DELTA_APPLY)
- ROLE_ELIGIBILITY_SET (parent=REPUTATION_THRESHOLD_CROSS)
- ROLE_ELIGIBILITY_REVOKE (parent=REPUTATION_THRESHOLD_CROSS)
- ACCOUNT_BAN (parent=DISPUTE_RESOLVE)
- ACCOUNT_REINSTATE (parent=DISPUTE_RESOLVE)

This module is also the single source of truth for *how* reputation is applied
(clamp + auto-ban). Other domains (e.g., consensus slashing) may call the
exported helper `apply_reputation_delta_system()` to apply consensus-proven
penalties deterministically without duplicating logic.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


# ---------------------------------------------------------------------------
# Constants (hard protocol)
# ---------------------------------------------------------------------------

REP_MIN: float = -100.0
REP_MAX: float = 100.0


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


@dataclass
class ReputationApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _as_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _clamp_rep(v: float) -> float:
    if v < REP_MIN:
        return REP_MIN
    if v > REP_MAX:
        return REP_MAX
    return v


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise ReputationApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_root_list(obj: Json, key: str) -> List[Any]:
    cur = obj.get(key)
    if not isinstance(cur, list):
        cur = []
        obj[key] = cur
    return cur


def _ensure_reputation(state: Json) -> Json:
    r = _ensure_root_dict(state, "reputation")
    r["deltas"] = _ensure_root_list(r, "deltas")
    r["threshold_crossings"] = _ensure_root_list(r, "threshold_crossings")

    if not isinstance(r.get("role_eligibility"), dict):
        r["role_eligibility"] = {}
    if not isinstance(r.get("bans"), dict):
        r["bans"] = {}
    return r


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

    # Ensure fields exist
    acct.setdefault("banned", False)
    acct.setdefault("reputation", 0.0)
    return acct


def _mk_id(prefix: str, env: TxEnvelope, provided: Any) -> str:
    p = _as_str(provided).strip()
    if p:
        return p
    return f"{prefix}:{env.signer}:{int(getattr(env, 'nonce', 0) or 0)}"


def _pick_account(payload: Json, *keys: str) -> str:
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _find_by_id(items: List[Any], key: str, value: str) -> Optional[Json]:
    for it in items:
        if isinstance(it, dict) and _as_str(it.get(key)).strip() == value:
            return it
    return None


def _apply_rep_delta_and_autoban(
    state: Json,
    *,
    account_id: str,
    delta: float,
    at_nonce: int,
    reason: str,
    payload: Json,
    ban_audit_nonce: int,
) -> Tuple[float, bool]:
    """Apply delta to accounts[account_id].reputation with clamp and auto-ban.

    Returns: (new_reputation, newly_banned)
    """
    acct = _ensure_account(state, account_id)

    cur = float(_as_float(acct.get("reputation"), 0.0))
    nxt = _clamp_rep(cur + float(delta))
    acct["reputation"] = float(nxt)

    newly_banned = False
    if float(nxt) <= REP_MIN and not bool(acct.get("banned", False)):
        acct["banned"] = True
        newly_banned = True

        rep = _ensure_reputation(state)
        bans = rep.get("bans")
        assert isinstance(bans, dict)

        prior = bans.get(account_id)
        if not (
            isinstance(prior, dict)
            and bool(prior.get("banned"))
            and _as_int(prior.get("set_at_nonce"), 0) == int(ban_audit_nonce)
        ):
            bans[account_id] = {
                "account_id": account_id,
                "banned": True,
                "set_at_nonce": int(ban_audit_nonce),
                "reason": reason or "auto_ban_reputation_floor",
                "payload": payload,
                "auto": True,
            }

    return float(nxt), newly_banned


# ---------------------------------------------------------------------------
# Exported helper for other domains
# ---------------------------------------------------------------------------


def apply_reputation_delta_system(
    state: Json,
    *,
    account_id: str,
    delta: float,
    reason: str,
    evidence: Json,
    at_nonce: int,
) -> Json:
    """Apply a reputation delta deterministically (SYSTEM provenance).

    Intended usage: consensus-proven penalties (e.g., slashing execution).

    This does not create a separate canon receipt; it mutates state using the
    same clamp + auto-ban semantics as REPUTATION_DELTA_APPLY.

    The resulting audit entry is appended to state["reputation"]["deltas"].
    """
    rep = _ensure_reputation(state)
    deltas = rep.get("deltas")
    assert isinstance(deltas, list)

    # Deterministic delta_id from evidence fields if provided
    delta_id = _as_str(evidence.get("delta_id") or evidence.get("id") or "").strip()
    if not delta_id:
        stable = _as_str(evidence.get("slash_id") or evidence.get("parent") or evidence.get("proof") or "")
        delta_id = f"repdelta:system:{account_id}:{stable}:{int(at_nonce)}" if stable else f"repdelta:system:{account_id}:{int(at_nonce)}"

    if _find_by_id(deltas, "delta_id", delta_id) is None:
        deltas.append(
            {
                "delta_id": delta_id,
                "account_id": account_id,
                "delta": float(delta),
                "reason": _as_str(reason).strip(),
                "at_nonce": int(at_nonce),
                "payload": evidence,
            }
        )

    new_rep, newly_banned = _apply_rep_delta_and_autoban(
        state,
        account_id=account_id,
        delta=float(delta),
        at_nonce=int(at_nonce),
        reason=_as_str(reason).strip(),
        payload=evidence,
        ban_audit_nonce=int(at_nonce),
    )

    return {"ok": True, "account_id": account_id, "reputation": float(new_rep), "newly_banned": bool(newly_banned)}


# ---------------------------------------------------------------------------
# Canon receipt txs
# ---------------------------------------------------------------------------


def _apply_reputation_delta_apply(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    rep = _ensure_reputation(state)
    payload = _as_dict(env.payload)

    account_id = _pick_account(payload, "account_id", "target", "account", "user")
    if not account_id:
        raise ReputationApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    if "delta" not in payload:
        raise ReputationApplyError("invalid_payload", "missing_delta", {"tx_type": env.tx_type})

    delta_raw = payload.get("delta")
    try:
        delta_val = float(int(delta_raw))
    except Exception:
        delta_val = _as_float(delta_raw, default=0.0)

    delta_id = _mk_id("repdelta", env, payload.get("delta_id") or payload.get("id"))
    reason = _as_str(payload.get("reason")).strip()

    deltas = rep["deltas"]
    already = _find_by_id(deltas, "delta_id", delta_id) is not None
    if not already:
        deltas.append(
            {
                "delta_id": delta_id,
                "account_id": account_id,
                "delta": float(delta_val),
                "reason": reason,
                "at_nonce": int(env.nonce),
                "payload": payload,
            }
        )

    new_rep, newly_banned = _apply_rep_delta_and_autoban(
        state,
        account_id=account_id,
        delta=float(delta_val),
        at_nonce=int(env.nonce),
        reason=reason,
        payload=payload,
        ban_audit_nonce=int(env.nonce),
    )

    return {
        "applied": "REPUTATION_DELTA_APPLY",
        "delta_id": delta_id,
        "account_id": account_id,
        "deduped": bool(already),
        "reputation": float(new_rep),
        "newly_banned": bool(newly_banned),
    }


def _apply_reputation_threshold_cross(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    rep = _ensure_reputation(state)
    payload = _as_dict(env.payload)

    account_id = _pick_account(payload, "account_id", "target", "account", "user")
    threshold = _as_str(payload.get("threshold") or payload.get("threshold_id")).strip()
    direction = _as_str(payload.get("direction")).strip().lower()

    if not account_id:
        raise ReputationApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if not threshold:
        raise ReputationApplyError("invalid_payload", "missing_threshold", {"tx_type": env.tx_type})
    if direction and direction not in {"up", "down", "above", "below", "cross"}:
        raise ReputationApplyError("invalid_payload", "bad_direction", {"direction": direction})

    cross_id = _mk_id("repcross", env, payload.get("cross_id") or payload.get("id"))
    crossings = rep["threshold_crossings"]
    already = _find_by_id(crossings, "cross_id", cross_id) is not None
    if not already:
        crossings.append(
            {
                "cross_id": cross_id,
                "account_id": account_id,
                "threshold": threshold,
                "direction": direction or "cross",
                "at_nonce": int(env.nonce),
                "payload": payload,
            }
        )

    return {"applied": "REPUTATION_THRESHOLD_CROSS", "cross_id": cross_id, "account_id": account_id, "deduped": bool(already)}


def _apply_role_eligibility_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    rep = _ensure_reputation(state)
    payload = _as_dict(env.payload)

    account_id = _pick_account(payload, "account_id", "target", "account", "user")
    role = _as_str(payload.get("role")).strip()
    if not account_id:
        raise ReputationApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if not role:
        raise ReputationApplyError("invalid_payload", "missing_role", {"tx_type": env.tx_type})

    elig = rep["role_eligibility"]
    assert isinstance(elig, dict)
    rec = elig.get(account_id)
    if not isinstance(rec, dict):
        rec = {"roles": {}, "updated_at_nonce": 0}

    roles = rec.get("roles")
    if not isinstance(roles, dict):
        roles = {}

    already = bool(roles.get(role)) is True and _as_int(rec.get("updated_at_nonce"), 0) == int(env.nonce)
    roles[role] = True
    rec["roles"] = roles
    rec["updated_at_nonce"] = int(env.nonce)
    rec["last_payload"] = payload
    elig[account_id] = rec

    return {"applied": "ROLE_ELIGIBILITY_SET", "account_id": account_id, "role": role, "deduped": bool(already)}


def _apply_role_eligibility_revoke(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    rep = _ensure_reputation(state)
    payload = _as_dict(env.payload)

    account_id = _pick_account(payload, "account_id", "target", "account", "user")
    role = _as_str(payload.get("role")).strip()
    if not account_id:
        raise ReputationApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if not role:
        raise ReputationApplyError("invalid_payload", "missing_role", {"tx_type": env.tx_type})

    elig = rep["role_eligibility"]
    assert isinstance(elig, dict)
    rec = elig.get(account_id)
    if not isinstance(rec, dict):
        rec = {"roles": {}, "updated_at_nonce": 0}

    roles = rec.get("roles")
    if not isinstance(roles, dict):
        roles = {}

    already = (role in roles and bool(roles.get(role)) is False) and _as_int(rec.get("updated_at_nonce"), 0) == int(env.nonce)
    roles[role] = False
    rec["roles"] = roles
    rec["updated_at_nonce"] = int(env.nonce)
    rec["last_payload"] = payload
    elig[account_id] = rec

    return {"applied": "ROLE_ELIGIBILITY_REVOKE", "account_id": account_id, "role": role, "deduped": bool(already)}


def _apply_account_ban(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    rep = _ensure_reputation(state)
    payload = _as_dict(env.payload)

    account_id = _pick_account(payload, "account_id", "target", "account", "user")
    if not account_id:
        raise ReputationApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    reason = _as_str(payload.get("reason")).strip()

    bans = rep["bans"]
    assert isinstance(bans, dict)
    prior = bans.get(account_id)
    already = isinstance(prior, dict) and bool(prior.get("banned")) and _as_int(prior.get("set_at_nonce"), 0) == int(env.nonce)

    bans[account_id] = {
        "account_id": account_id,
        "banned": True,
        "set_at_nonce": int(env.nonce),
        "reason": reason,
        "payload": payload,
        "auto": False,
    }

    acct = _ensure_account(state, account_id)
    acct["banned"] = True

    return {"applied": "ACCOUNT_BAN", "account_id": account_id, "deduped": bool(already)}


def _apply_account_reinstate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    rep = _ensure_reputation(state)
    payload = _as_dict(env.payload)

    account_id = _pick_account(payload, "account_id", "target", "account", "user")
    if not account_id:
        raise ReputationApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    bans = rep["bans"]
    assert isinstance(bans, dict)
    prior = bans.get(account_id)
    already = isinstance(prior, dict) and (not bool(prior.get("banned"))) and _as_int(prior.get("set_at_nonce"), 0) == int(env.nonce)

    reason = _as_str(payload.get("reason")).strip()
    bans[account_id] = {
        "account_id": account_id,
        "banned": False,
        "set_at_nonce": int(env.nonce),
        "reason": reason,
        "payload": payload,
        "auto": False,
    }

    acct = _ensure_account(state, account_id)
    acct["banned"] = False

    # Optional: keep reputation as-is (do not reset). Protocol chooses not to reset.
    # If you later want reinstate to bump reputation upward, do it explicitly via REPUTATION_DELTA_APPLY.

    return {"applied": "ACCOUNT_REINSTATE", "account_id": account_id, "deduped": bool(already)}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

REPUTATION_TX_TYPES: Set[str] = {
    "REPUTATION_DELTA_APPLY",
    "REPUTATION_THRESHOLD_CROSS",
    "ROLE_ELIGIBILITY_SET",
    "ROLE_ELIGIBILITY_REVOKE",
    "ACCOUNT_BAN",
    "ACCOUNT_REINSTATE",
}


def apply_reputation(state: Json, env: TxEnvelope) -> Optional[Json]:
    """Apply Reputation txs. Returns meta dict if handled; otherwise None."""
    t = str(env.tx_type or "").strip().upper()
    if t not in REPUTATION_TX_TYPES:
        return None

    if t == "REPUTATION_DELTA_APPLY":
        return _apply_reputation_delta_apply(state, env)
    if t == "REPUTATION_THRESHOLD_CROSS":
        return _apply_reputation_threshold_cross(state, env)
    if t == "ROLE_ELIGIBILITY_SET":
        return _apply_role_eligibility_set(state, env)
    if t == "ROLE_ELIGIBILITY_REVOKE":
        return _apply_role_eligibility_revoke(state, env)
    if t == "ACCOUNT_BAN":
        return _apply_account_ban(state, env)
    if t == "ACCOUNT_REINSTATE":
        return _apply_account_reinstate(state, env)

    return None
