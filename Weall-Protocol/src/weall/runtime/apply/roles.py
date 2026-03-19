# NOTE: full file is large; only showing the complete file is required by your preference.
# This is the complete file content.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.ledger.roles_schema import ensure_roles_schema, set_treasury_signers
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


@dataclass
class RolesApplyError(Exception):
    code: str
    reason: str
    details: Json | None = None

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}"


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _touch(by_id: Json, acct: str) -> Json:
    rec = by_id.get(acct)
    if not isinstance(rec, dict):
        rec = {"account_id": acct, "enrolled": False, "active": False}
    rec.setdefault("account_id", acct)
    return rec


def _pick_account(payload: Json, *keys: str) -> str:
    for k in keys:
        v = payload.get(k)
        s = _as_str(v).strip()
        if s:
            return s
    return ""


def _ensure_roles(ledger: Json) -> Json:
    ensure_roles_schema(ledger)
    roles = ledger.get("roles")
    return roles if isinstance(roles, dict) else {}


def _require_system_env(env: TxEnvelope) -> None:
    if bool(getattr(env, "system", False)) or _as_str(getattr(env, "signer", "")) == "SYSTEM":
        return
    raise RolesApplyError(
        "forbidden", "system_tx_required", {"tx_type": env.tx_type, "signer": env.signer}
    )


PROTOCOL_TREASURY_ID = "TREASURY_PROTOCOL"


def _sync_protocol_treasury_from_emissaries(ledger: Json, *, reason: str, nonce: int) -> None:
    """Keep the protocol treasury signer set in lockstep with the seated emissary set.

    Design goals:
      - One global protocol treasury exists from genesis.
      - It is emissary-controlled (require_emissary_signers=true).
      - Signers should automatically become the currently seated emissaries.
      - Enforce multisig semantics: do not enable (set signers/threshold) until at least 2 emissaries are seated.
      - Preserve the configured threshold where possible, but never exceed signer count and never drop below 2.
    """
    roles = _ensure_roles(ledger)
    treasuries = roles.get("treasuries_by_id")
    if not isinstance(treasuries, dict):
        return

    obj = treasuries.get(PROTOCOL_TREASURY_ID)
    if not isinstance(obj, dict):
        return

    # Only sync if this treasury is explicitly emissary-controlled.
    if not bool(obj.get("require_emissary_signers", False)):
        return

    # Allow opting out of auto-sync in genesis or via governance/system maintenance.
    if obj.get("auto_sync_emissaries", True) is False:
        return

    em = roles.get("emissaries")
    seated: list[str] = []
    if isinstance(em, dict) and isinstance(em.get("seated"), list):
        seated = [str(x).strip() for x in em.get("seated") if str(x).strip()]
    seated = sorted(set([s for s in seated if s]))

    # Keep the treasury inert until we have at least 2 emissaries (multisig semantics).
    if len(seated) < 2:
        return

    existing_signers = obj.get("signers")
    existing_signers = (
        sorted(set([str(x).strip() for x in existing_signers if str(x).strip()]))
        if isinstance(existing_signers, list)
        else []
    )
    existing_threshold = _as_int(obj.get("threshold"), 2)
    if existing_threshold < 2:
        existing_threshold = 2

    desired_threshold = min(max(2, existing_threshold), len(seated))

    # No-op if already synced.
    if (
        existing_signers == seated
        and _as_int(obj.get("threshold"), desired_threshold) == desired_threshold
    ):
        return

    # Normalize via schema helper then re-attach metadata.
    set_treasury_signers(ledger, PROTOCOL_TREASURY_ID, seated, threshold=desired_threshold)

    treasuries = roles.get("treasuries_by_id")
    obj2 = treasuries.get(PROTOCOL_TREASURY_ID) if isinstance(treasuries, dict) else None
    if isinstance(obj2, dict):
        obj2["require_emissary_signers"] = True
        obj2.setdefault("label", "protocol")
        obj2.setdefault("auto_sync_emissaries", True)
        obj2["updated_at_nonce"] = int(nonce)
        obj2["synced_from_emissaries_at_nonce"] = int(nonce)
        obj2["synced_from_emissaries_reason"] = str(reason)
        treasuries[PROTOCOL_TREASURY_ID] = obj2


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
    acct = _pick_account(payload, "account_id", "juror", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = jur.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        jur["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("enrolled", False))
    rec["enrolled"] = True
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

    rec["active"] = True
    rec["activated_at_nonce"] = int(env.nonce)
    by_id[acct] = rec
    jur["by_id"] = by_id

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
    jur["by_id"] = by_id

    aset = jur.get("active_set")
    if not isinstance(aset, list):
        aset = []
    if acct in aset:
        aset = sorted([a for a in aset if a != acct])
    jur["active_set"] = aset
    return {"applied": "ROLE_JUROR_SUSPEND", "account_id": acct, "deduped": already}


def _apply_role_juror_reinstate(ledger: Json, env: TxEnvelope) -> Json:
    # Alias for activate in MVP
    return _apply_role_juror_activate(ledger, env)


# ---------------------------------------------------------------------------
# Validators role
# ---------------------------------------------------------------------------


def _apply_role_validator_activate(ledger: Json, env: TxEnvelope) -> Json:
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
    had = acct in aset
    if not had:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
    validators["active_set"] = aset
    roles["validators"] = validators
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
        aset = sorted([a for a in aset if a != acct])
    validators["active_set"] = aset
    roles["validators"] = validators
    return {"applied": "ROLE_VALIDATOR_SUSPEND", "account_id": acct, "deduped": already}


# ---------------------------------------------------------------------------
# Node Operators role
# ---------------------------------------------------------------------------


def _apply_role_node_operator_enroll(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("enrolled", False))
    rec["enrolled"] = True
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
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "node_operator_not_enrolled", {"account_id": acct})

    rec["active"] = True
    rec["activated_at_nonce"] = int(env.nonce)
    by_id[acct] = rec
    ops["by_id"] = by_id

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
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "node_operator_not_enrolled", {"account_id": acct})

    already = not bool(rec.get("active", False))
    rec["active"] = False
    rec["suspended_at_nonce"] = int(env.nonce)
    by_id[acct] = rec
    ops["by_id"] = by_id

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
    _sync_protocol_treasury_from_emissaries(ledger, reason="emissary_seated", nonce=int(env.nonce))
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
    _sync_protocol_treasury_from_emissaries(ledger, reason="emissary_removed", nonce=int(env.nonce))
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

    already = _as_str(gov_exec.get("current")).strip() == acct and bool(
        gov_exec.get("active", True)
    )
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
    is_system = (
        bool(getattr(env, "system", False))
        or str(getattr(env, "signer", "") or "").strip() == "SYSTEM"
    )

    treasuries[treasury_id] = {
        "signers": [env.signer],
        "threshold": 2 if is_system else 1,
        "created_by": env.signer,
        "created_at_nonce": int(env.nonce),
        # Protocol treasuries are expected to be controlled by seated emissaries.
        # For system-created treasuries, default to requiring emissary signers.
        "require_emissary_signers": bool(is_system),
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

    t_obj = treasuries.get(treasury_id)
    require_emissary = (
        bool(t_obj.get("require_emissary_signers", False)) if isinstance(t_obj, dict) else False
    )

    signers = [s for s in _as_list(payload.get("signers")) if isinstance(s, str) and s.strip()]
    # deterministic uniq sort
    signers = sorted(set([s.strip() for s in signers if s.strip()]))

    if not signers:
        raise RolesApplyError("invalid_payload", "missing_signers", {"treasury_id": treasury_id})

    threshold = _as_int(payload.get("threshold"), 1)
    if threshold <= 0:
        threshold = 1

    # If this treasury is flagged as emissary-controlled, enforce that the signer
    # set is a subset of currently seated emissaries and that threshold is at least 2.
    if require_emissary:
        em = roles.get("emissaries")
        seated = []
        if isinstance(em, dict) and isinstance(em.get("seated"), list):
            seated = [str(x).strip() for x in em.get("seated") if str(x).strip()]
        seated_set = set(seated)
        bad = [s for s in signers if s not in seated_set]
        if bad:
            raise RolesApplyError(
                "forbidden",
                "treasury_signers_must_be_seated_emissaries",
                {"treasury_id": treasury_id, "bad_signers": bad},
            )
        if threshold < 2:
            threshold = 2
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

ROLES_TX_TYPES: set[str] = {
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


def apply_roles(ledger: Json, env: TxEnvelope) -> Json | None:
    t = _as_str(env.tx_type).strip().upper()
    if t not in ROLES_TX_TYPES:
        return None

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


__all__ = ["ROLES_TX_TYPES", "RolesApplyError", "apply_roles"]
