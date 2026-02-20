from __future__ import annotations

"""
Roles domain apply semantics.

Canon Roles txs (v1.22.1+) handled here:
- ROLE_JUROR_* (enroll/activate/suspend/reinstate)
- ROLE_VALIDATOR_* (activate/suspend)
- ROLE_NODE_OPERATOR_* (enroll/activate/suspend)
- ROLE_EMISSARY_* (nominate/vote/seat/remove)
- ROLE_GOV_EXECUTOR_SET

Also includes MVP authority txs used by runtime apply tests:
- TREASURY_CREATE
- TREASURY_SIGNERS_SET
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.ledger.roles_schema import ensure_roles_schema, set_treasury_signers
from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@dataclass
class RolesApplyError(RuntimeError):
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


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise RolesApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_roles(state: Json) -> Json:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    # Ensure canonical schema roots exist (non-destructive)
    ensure_roles_schema(state)
    roles = state.get("roles")
    return roles if isinstance(roles, dict) else {}


def _pick_account(payload: Json, *keys: str) -> str:
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _touch(by_id: Json, acct: str) -> Json:
    cur = by_id.get(acct)
    if not isinstance(cur, dict):
        cur = {"account_id": acct}
    return cur


# ---------------------------------------------------------------------------
# Jurors role
# ---------------------------------------------------------------------------

def _apply_role_juror_enroll(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    jur = roles.get("jurors")
    if not isinstance(jur, dict):
        jur = {"by_id": {}, "active_set": []}
        roles["jurors"] = jur

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "juror", "target", "account") or env.signer
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = jur.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        jur["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("enrolled", False))
    rec["enrolled"] = True
    rec.setdefault("active", False)
    rec["enrolled_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    jur["by_id"] = by_id
    return {"applied": "ROLE_JUROR_ENROLL", "account_id": acct, "deduped": had}


def _apply_role_juror_activate(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    jur = roles.get("jurors")
    if not isinstance(jur, dict):
        jur = {"by_id": {}, "active_set": []}
        roles["jurors"] = jur

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "juror", "target", "account") or env.signer
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = jur.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        jur["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "juror_not_enrolled", {"account_id": acct})

    rec["active"] = True
    rec["activated_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    aset = jur.get("active_set")
    if not isinstance(aset, list):
        aset = []
    had = acct in aset
    if not had:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
    jur["active_set"] = aset
    return {"applied": "ROLE_JUROR_ACTIVATE", "account_id": acct, "deduped": had}


def _apply_role_juror_suspend(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    jur = roles.get("jurors")
    if not isinstance(jur, dict):
        jur = {"by_id": {}, "active_set": []}
        roles["jurors"] = jur

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "juror", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = jur.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        jur["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "juror_not_enrolled", {"account_id": acct})

    already = not bool(rec.get("active", False))
    rec["active"] = False
    rec["suspended_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    aset = jur.get("active_set")
    if not isinstance(aset, list):
        aset = []
    if acct in aset:
        aset = sorted([a for a in aset if a != acct])
    jur["active_set"] = aset
    return {"applied": "ROLE_JUROR_SUSPEND", "account_id": acct, "deduped": already}


def _apply_role_juror_reinstate(ledger: Json, env: TxEnvelope) -> Json:
    # Reinstate => active
    return _apply_role_juror_activate(ledger, env)


# ---------------------------------------------------------------------------
# Validators role (activate/suspend pointers)
# ---------------------------------------------------------------------------

def _apply_role_validator_activate(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {"active_set": []}
        roles["validators"] = validators

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "validator", "target", "account") or env.signer
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    aset = validators.get("active_set")
    if not isinstance(aset, list):
        aset = []

    had = acct in aset
    if not had:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
        validators["active_set"] = aset

    return {"applied": "ROLE_VALIDATOR_ACTIVATE", "account_id": acct, "deduped": had}


def _apply_role_validator_suspend(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {"active_set": []}
        roles["validators"] = validators

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "validator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    aset = validators.get("active_set")
    if not isinstance(aset, list):
        aset = []

    already = acct not in aset
    if acct in aset:
        validators["active_set"] = sorted([a for a in aset if a != acct])

    return {"applied": "ROLE_VALIDATOR_SUSPEND", "account_id": acct, "deduped": already}


# ---------------------------------------------------------------------------
# Node Operators role (enroll/activate/suspend)
# ---------------------------------------------------------------------------

def _apply_role_node_operator_enroll(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "target", "account") or env.signer
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("enrolled", False))
    rec["enrolled"] = True
    rec.setdefault("active", False)
    rec["enrolled_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    ops["by_id"] = by_id
    return {"applied": "ROLE_NODE_OPERATOR_ENROLL", "account_id": acct, "deduped": had}


def _apply_role_node_operator_activate(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "target", "account") or env.signer
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "operator_not_enrolled", {"account_id": acct})

    rec["active"] = True
    rec["activated_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    aset = ops.get("active_set")
    if not isinstance(aset, list):
        aset = []
    had = acct in aset
    if not had:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
    ops["active_set"] = aset
    return {"applied": "ROLE_NODE_OPERATOR_ACTIVATE", "account_id": acct, "deduped": had}


def _apply_role_node_operator_suspend(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "operator_not_enrolled", {"account_id": acct})

    already = not bool(rec.get("active", False))
    rec["active"] = False
    rec["suspended_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    aset = ops.get("active_set")
    if not isinstance(aset, list):
        aset = []
    if acct in aset:
        aset = sorted([a for a in aset if a != acct])
    ops["active_set"] = aset
    return {"applied": "ROLE_NODE_OPERATOR_SUSPEND", "account_id": acct, "deduped": already}


# ---------------------------------------------------------------------------
# Emissaries role (nominate/vote/seat/remove)
# ---------------------------------------------------------------------------

def _apply_role_emissary_nominate(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    target = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not target:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    noms = em.get("nominations")
    if not isinstance(noms, dict):
        noms = {}
        em["nominations"] = noms

    nom = noms.get(target)
    if not isinstance(nom, dict):
        nom = {"account_id": target, "votes": [], "created_at_nonce": int(env.nonce)}
    votes = nom.get("votes")
    if not isinstance(votes, list):
        votes = []
    # nominee auto-vote by nominator
    if env.signer not in votes:
        votes.append(env.signer)
    nom["votes"] = votes
    noms[target] = nom
    em["nominations"] = noms

    return {"applied": "ROLE_EMISSARY_NOMINATE", "account_id": target}


def _apply_role_emissary_vote(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    target = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not target:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    noms = em.get("nominations")
    if not isinstance(noms, dict):
        raise RolesApplyError("not_found", "no_nominations", {})

    nom = noms.get(target)
    if not isinstance(nom, dict):
        raise RolesApplyError("not_found", "nomination_not_found", {"account_id": target})

    votes = nom.get("votes")
    if not isinstance(votes, list):
        votes = []
    had = env.signer in votes
    if not had:
        votes.append(env.signer)
    nom["votes"] = votes
    noms[target] = nom
    em["nominations"] = noms

    return {"applied": "ROLE_EMISSARY_VOTE", "account_id": target, "deduped": had}


def _apply_role_emissary_seat(ledger: Json, env: TxEnvelope) -> Json:
    # This is a system action in many designs; keep permissive unless canon forbids.
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = em.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        em["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("active", False))
    rec["active"] = True
    rec["seated_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    seated = em.get("seated")
    if not isinstance(seated, list):
        seated = []
    if acct not in seated:
        seated = sorted({*(str(x) for x in seated if str(x).strip()), acct})
    em["seated"] = seated
    return {"applied": "ROLE_EMISSARY_SEAT", "account_id": acct, "deduped": had}


def _apply_role_emissary_remove(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = em.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        em["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("active", False))
    rec["active"] = False
    rec["removed"] = True
    rec["removed_at_nonce"] = int(env.nonce)
    if isinstance(payload.get("reason"), str):
        rec["remove_reason"] = payload.get("reason")
    by_id[acct] = rec

    seated = em.get("seated")
    if not isinstance(seated, list):
        seated = []
    if acct in seated:
        seated = sorted([a for a in seated if a != acct])
    em["seated"] = seated
    return {"applied": "ROLE_EMISSARY_REMOVE", "account_id": acct, "deduped": (not had)}


# ---------------------------------------------------------------------------
# Gov Executor role pointer
# ---------------------------------------------------------------------------

def _apply_role_gov_executor_set(ledger: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    roles = _ensure_roles(ledger)
    gov_exec = roles.get("gov_executor")
    if not isinstance(gov_exec, dict):
        gov_exec = {"current": "", "active": True}
        roles["gov_executor"] = gov_exec

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "executor", "target", "account", "gov_executor")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    already = _as_str(gov_exec.get("current")).strip() == acct and bool(gov_exec.get("active", True))
    gov_exec["current"] = acct
    gov_exec["active"] = True
    gov_exec["set_at_nonce"] = int(env.nonce)
    if isinstance(payload.get("note"), str):
        gov_exec["note"] = payload.get("note")
    roles["gov_executor"] = gov_exec

    return {"applied": "ROLE_GOV_EXECUTOR_SET", "account_id": acct, "deduped": already}


# ---------------------------------------------------------------------------
# MVP Treasury role authority (TREASURY_CREATE / TREASURY_SIGNERS_SET)
# ---------------------------------------------------------------------------

def _apply_treasury_create(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    payload = _as_dict(env.payload)

    treasury_id = _as_str(payload.get("treasury_id") or payload.get("id")).strip()
    if not treasury_id:
        raise RolesApplyError("invalid_payload", "missing_treasury_id", {"tx_type": env.tx_type})

    treasuries = roles.get("treasuries_by_id")
    if not isinstance(treasuries, dict):
        treasuries = {}
        roles["treasuries_by_id"] = treasuries

    if treasury_id in treasuries:
        raise RolesApplyError("duplicate", "treasury_id_exists", {"treasury_id": treasury_id})

    # Default signer set = creator, threshold=1
    treasuries[treasury_id] = {
        "signers": [env.signer],
        "threshold": 1,
        "created_by": env.signer,
        "created_at_nonce": int(env.nonce),
    }
    roles["treasuries_by_id"] = treasuries
    return {"applied": "TREASURY_CREATE", "treasury_id": treasury_id}


def _apply_treasury_signers_set(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    payload = _as_dict(env.payload)

    treasury_id = _as_str(payload.get("treasury_id") or payload.get("id")).strip()
    if not treasury_id:
        raise RolesApplyError("invalid_payload", "missing_treasury_id", {"tx_type": env.tx_type})

    treasuries = roles.get("treasuries_by_id")
    if not isinstance(treasuries, dict) or not isinstance(treasuries.get(treasury_id), dict):
        raise RolesApplyError("not_found", "treasury_not_found", {"treasury_id": treasury_id})

    signers = [s for s in _as_list(payload.get("signers")) if isinstance(s, str) and s.strip()]
    # deterministic uniq sort
    signers = sorted(set([s.strip() for s in signers if s.strip()]))

    if not signers:
        raise RolesApplyError("invalid_payload", "missing_signers", {"treasury_id": treasury_id})

    threshold = _as_int(payload.get("threshold"), 1)
    if threshold <= 0:
        threshold = 1
    if threshold > len(signers):
        raise RolesApplyError(
            "bad_payload",
            "threshold_exceeds_signers",
            {"treasury_id": treasury_id, "threshold": threshold, "n_signers": len(signers)},
        )

    # Use schema helper to normalize
    set_treasury_signers(ledger, treasury_id, signers, threshold=threshold)

    # Preserve metadata
    treasuries = roles.get("treasuries_by_id")
    obj = treasuries.get(treasury_id) if isinstance(treasuries, dict) else None
    if isinstance(obj, dict):
        obj["updated_at_nonce"] = int(env.nonce)
        treasuries[treasury_id] = obj

    return {
        "applied": "TREASURY_SIGNERS_SET",
        "treasury_id": treasury_id,
        "threshold": threshold,
        "n_signers": len(signers),
    }


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

ROLES_TX_TYPES: Set[str] = {
    "ROLE_JUROR_ENROLL",
    "ROLE_JUROR_ACTIVATE",
    "ROLE_JUROR_SUSPEND",
    "ROLE_JUROR_REINSTATE",
    "ROLE_VALIDATOR_ACTIVATE",
    "ROLE_VALIDATOR_SUSPEND",
    "ROLE_NODE_OPERATOR_ENROLL",
    "ROLE_NODE_OPERATOR_ACTIVATE",
    "ROLE_NODE_OPERATOR_SUSPEND",
    "ROLE_EMISSARY_NOMINATE",
    "ROLE_EMISSARY_VOTE",
    "ROLE_EMISSARY_SEAT",
    "ROLE_EMISSARY_REMOVE",
    "ROLE_GOV_EXECUTOR_SET",
    "TREASURY_CREATE",
    "TREASURY_SIGNERS_SET",
}


def apply_roles(ledger: Json, env: TxEnvelope) -> Optional[Json]:
    """Apply Roles txs. Returns meta dict if handled; otherwise None."""
    t = str(env.tx_type or "").strip()
    if t not in ROLES_TX_TYPES:
        return None

    # Ensure schema roots exist (non-destructive)
    _ensure_roles(ledger)

    if t == "ROLE_JUROR_ENROLL":
        return _apply_role_juror_enroll(ledger, env)
    if t == "ROLE_JUROR_ACTIVATE":
        return _apply_role_juror_activate(ledger, env)
    if t == "ROLE_JUROR_SUSPEND":
        return _apply_role_juror_suspend(ledger, env)
    if t == "ROLE_JUROR_REINSTATE":
        return _apply_role_juror_reinstate(ledger, env)

    if t == "ROLE_VALIDATOR_ACTIVATE":
        return _apply_role_validator_activate(ledger, env)
    if t == "ROLE_VALIDATOR_SUSPEND":
        return _apply_role_validator_suspend(ledger, env)

    if t == "ROLE_NODE_OPERATOR_ENROLL":
        return _apply_role_node_operator_enroll(ledger, env)
    if t == "ROLE_NODE_OPERATOR_ACTIVATE":
        return _apply_role_node_operator_activate(ledger, env)
    if t == "ROLE_NODE_OPERATOR_SUSPEND":
        return _apply_role_node_operator_suspend(ledger, env)

    if t == "ROLE_EMISSARY_NOMINATE":
        return _apply_role_emissary_nominate(ledger, env)
    if t == "ROLE_EMISSARY_VOTE":
        return _apply_role_emissary_vote(ledger, env)
    if t == "ROLE_EMISSARY_SEAT":
        return _apply_role_emissary_seat(ledger, env)
    if t == "ROLE_EMISSARY_REMOVE":
        return _apply_role_emissary_remove(ledger, env)

    if t == "ROLE_GOV_EXECUTOR_SET":
        return _apply_role_gov_executor_set(ledger, env)

    if t == "TREASURY_CREATE":
        return _apply_treasury_create(ledger, env)
    if t == "TREASURY_SIGNERS_SET":
        return _apply_treasury_signers_set(ledger, env)

    return None
