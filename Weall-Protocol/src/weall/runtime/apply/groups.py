# src/weall/runtime/apply/groups.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class GroupsApplyError(Exception):
    code: str
    reason: str
    details: Optional[Json] = None

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}"


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _ensure_groups_root(state: Json) -> Json:
    g = state.get("groups")
    if not isinstance(g, dict):
        g = {}
        state["groups"] = g
    return g


def _ensure_group_spends(state: Json) -> Json:
    root = state.get("group_treasury_spends")
    if not isinstance(root, dict):
        root = {}
        state["group_treasury_spends"] = root
    return root


GROUPS_TX_TYPES: Set[str] = {
    "GROUP_TREASURY_POLICY_SET",
    "GROUP_TREASURY_SPEND_EXPIRE",
    # Civic group core
    "GROUP_CREATE",
    "GROUP_UPDATE",
    "GROUP_ROLE_GRANT",
    "GROUP_ROLE_REVOKE",
    "GROUP_MEMBERSHIP_REQUEST",
    "GROUP_MEMBERSHIP_DECIDE",
    "GROUP_MEMBERSHIP_REMOVE",
    "GROUP_SIGNERS_SET",
    "GROUP_MODERATORS_SET",

    # Treasury subset
    "GROUP_TREASURY_CREATE",
    "GROUP_TREASURY_SPEND_PROPOSE",
    "GROUP_TREASURY_SPEND_SIGN",
    "GROUP_TREASURY_SPEND_CANCEL",
    "GROUP_TREASURY_SPEND_EXECUTE",
    "GROUP_TREASURY_AUDIT_ANCHOR_SET",
}


def _apply_group_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    if group_id in groups:
        raise GroupsApplyError("already_exists", "group_exists", {"group_id": group_id})

    groups[group_id] = {
        "group_id": group_id,
        "created_by": _as_str(env.signer).strip(),
        "charter": _as_str(payload.get("charter")).strip(),
        "meta": payload,
    }
    return {"applied": "GROUP_CREATE", "group_id": group_id}


def _apply_group_update(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    # MVP: allow any signer to update metadata (full permission model later)
    g["charter"] = _as_str(payload.get("charter", g.get("charter"))).strip()
    g["meta"] = payload
    groups[group_id] = g
    return {"applied": "GROUP_UPDATE", "group_id": group_id}


def _apply_group_role_grant(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    target = _as_str(payload.get("target")).strip()
    role = _as_str(payload.get("role")).strip().lower()

    if not group_id or not target or not role:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    roles = g.get("roles")
    if not isinstance(roles, dict):
        roles = {}
    user_roles = roles.get(target)
    if not isinstance(user_roles, list):
        user_roles = []
    if role not in user_roles:
        user_roles.append(role)
    roles[target] = user_roles
    g["roles"] = roles
    groups[group_id] = g
    return {"applied": "GROUP_ROLE_GRANT", "group_id": group_id, "target": target, "role": role}


def _apply_group_role_revoke(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    target = _as_str(payload.get("target")).strip()
    role = _as_str(payload.get("role")).strip().lower()

    if not group_id or not target or not role:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    roles = g.get("roles")
    if not isinstance(roles, dict):
        roles = {}
    user_roles = roles.get(target)
    if not isinstance(user_roles, list):
        user_roles = []
    user_roles = [r for r in user_roles if str(r).lower() != role]
    roles[target] = user_roles
    g["roles"] = roles
    groups[group_id] = g
    return {"applied": "GROUP_ROLE_REVOKE", "group_id": group_id, "target": target, "role": role}


def _apply_group_membership_request(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    if not group_id:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    reqs = g.get("membership_requests")
    if not isinstance(reqs, dict):
        reqs = {}
    reqs[_as_str(env.signer).strip()] = {"status": "pending", "at_nonce": int(env.nonce)}
    g["membership_requests"] = reqs
    groups[group_id] = g
    return {"applied": "GROUP_MEMBERSHIP_REQUEST", "group_id": group_id}


def _apply_group_membership_decide(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    target = _as_str(payload.get("target")).strip()
    decision = _as_str(payload.get("decision")).strip().lower()

    if not group_id or not target or decision not in ("approve", "deny"):
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    reqs = g.get("membership_requests")
    if not isinstance(reqs, dict) or target not in reqs:
        raise GroupsApplyError("not_found", "membership_request_not_found", {"group_id": group_id, "target": target})

    reqs[target] = {"status": decision, "decided_by": _as_str(env.signer).strip(), "at_nonce": int(env.nonce)}
    g["membership_requests"] = reqs

    if decision == "approve":
        members = g.get("members")
        if not isinstance(members, dict):
            members = {}
        members[target] = {"joined_at_nonce": int(env.nonce)}
        g["members"] = members

    groups[group_id] = g
    return {"applied": "GROUP_MEMBERSHIP_DECIDE", "group_id": group_id, "target": target, "decision": decision}


def _apply_group_membership_remove(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    target = _as_str(payload.get("target")).strip()

    if not group_id or not target:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    members = g.get("members")
    if not isinstance(members, dict) or target not in members:
        raise GroupsApplyError("not_found", "member_not_found", {"group_id": group_id, "target": target})

    members.pop(target, None)
    g["members"] = members
    groups[group_id] = g
    return {"applied": "GROUP_MEMBERSHIP_REMOVE", "group_id": group_id, "target": target}


def _apply_group_signers_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    signers = payload.get("signers")

    if not group_id or not isinstance(signers, list):
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    g["signers"] = [str(s).strip() for s in signers if str(s).strip()]
    groups[group_id] = g
    return {"applied": "GROUP_SIGNERS_SET", "group_id": group_id}


def _apply_group_moderators_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    group_id = _as_str(payload.get("group_id")).strip()
    moderators = payload.get("moderators")

    if not group_id or not isinstance(moderators, list):
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    groups = _ensure_groups_root(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": group_id})

    g["moderators"] = [str(m).strip() for m in moderators if str(m).strip()]
    groups[group_id] = g
    return {"applied": "GROUP_MODERATORS_SET", "group_id": group_id}


def _apply_group_treasury_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    treasury_id = _as_str(payload.get("treasury_id")).strip()
    if not treasury_id:
        raise GroupsApplyError("invalid_payload", "missing_treasury_id", {"tx_type": env.tx_type})

    # MVP: just claim it
    return {"applied": "GROUP_TREASURY_CREATE", "treasury_id": treasury_id}


def _apply_group_treasury_spend_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise GroupsApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    to = _as_str(payload.get("to")).strip()
    amount = payload.get("amount")
    if not to or amount is None:
        raise GroupsApplyError("invalid_payload", "missing_fields", {"tx_type": env.tx_type})

    spends = _ensure_group_spends(state)
    if spend_id in spends:
        raise GroupsApplyError("already_exists", "spend_exists", {"spend_id": spend_id})

    spends[spend_id] = {
        "spend_id": spend_id,
        "proposed_by": _as_str(env.signer).strip(),
        "to": to,
        "amount": int(amount),
        "status": "proposed",
        "signatures": {},
        "at_nonce": int(env.nonce),
        "payload": payload,
    }
    return {"applied": "GROUP_TREASURY_SPEND_PROPOSE", "spend_id": spend_id}


def _apply_group_treasury_spend_sign(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise GroupsApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise GroupsApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    sigs = s.get("signatures")
    if not isinstance(sigs, dict):
        sigs = {}
    sigs[env.signer] = {"at_nonce": int(env.nonce)}
    s["signatures"] = sigs
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_SIGN", "spend_id": spend_id}


def _apply_group_treasury_spend_cancel(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise GroupsApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise GroupsApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    status = _as_str(s.get("status")).strip().lower()
    if status in ("executed", "canceled", "cancelled"):
        return {"applied": "GROUP_TREASURY_SPEND_CANCEL", "spend_id": spend_id, "deduped": True}

    s["status"] = "canceled"
    s["canceled_by"] = _as_str(env.signer).strip()
    s["canceled_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_CANCEL", "spend_id": spend_id}


def _apply_group_treasury_spend_execute(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise GroupsApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise GroupsApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    status = _as_str(s.get("status")).strip().lower()
    if status == "executed":
        return {"applied": "GROUP_TREASURY_SPEND_EXECUTE", "spend_id": spend_id, "deduped": True}
    if status in ("canceled", "cancelled"):
        raise GroupsApplyError("forbidden", "spend_canceled", {"spend_id": spend_id})

    s["status"] = "executed"
    s["executed_by"] = _as_str(env.signer).strip()
    s["executed_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_EXECUTE", "spend_id": spend_id}


def _require_system(env: TxEnvelope) -> None:
    if bool(getattr(env, "system", False)) or _as_str(getattr(env, "signer", "")) == "SYSTEM":
        return
    raise GroupsApplyError("forbidden", "system_tx_required", {"tx_type": env.tx_type, "signer": env.signer})


def _apply_group_treasury_policy_set(state: Json, env: TxEnvelope) -> Json:
    """SYSTEM receipt-only: attach/update a group's treasury policy blob."""
    _require_system(env)
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    if not gid:
        raise GroupsApplyError("invalid_payload", "missing_group_id", {})
    groups = _ensure_groups_root(state)
    g = groups.get(gid)
    if not isinstance(g, dict):
        raise GroupsApplyError("not_found", "group_not_found", {"group_id": gid})
    # Store policy blob (or full payload if no nested "policy").
    g["treasury_policy"] = payload.get("policy") if isinstance(payload.get("policy"), dict) else payload
    g["treasury_policy_set_at_nonce"] = int(env.nonce)
    groups[gid] = g
    return {"applied": "GROUP_TREASURY_POLICY_SET", "group_id": gid}


def _ensure_group_spends_expired(state: Json) -> Json:
    root = state.get("group_treasury_spends_expired")
    if not isinstance(root, dict):
        root = {}
        state["group_treasury_spends_expired"] = root
    return root


def _apply_group_treasury_spend_expire(state: Json, env: TxEnvelope) -> Json:
    """SYSTEM receipt-only: expire a pending group treasury spend reference."""
    _require_system(env)
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not gid or not spend_id:
        raise GroupsApplyError(
            "invalid_payload",
            "missing_group_or_spend_id",
            {"group_id": gid, "spend_id": spend_id},
        )
    # Keep a global expired map (MVP) so receipts are queryable even if spend data is elsewhere.
    expired = _ensure_group_spends_expired(state)
    lst = expired.get(gid)
    if not isinstance(lst, list):
        lst = []
    lst.append({"spend_id": spend_id, "at_nonce": int(env.nonce), "payload": payload})
    expired[gid] = lst
    return {"applied": "GROUP_TREASURY_SPEND_EXPIRE", "group_id": gid, "spend_id": spend_id}


def apply_groups(state: Json, env: TxEnvelope) -> Optional[Json]:
    t = _as_str(env.tx_type).strip().upper()
    if t not in GROUPS_TX_TYPES:
        return None

    # Civic group core
    if t == "GROUP_CREATE":
        return _apply_group_create(state, env)
    if t == "GROUP_UPDATE":
        return _apply_group_update(state, env)
    if t == "GROUP_ROLE_GRANT":
        return _apply_group_role_grant(state, env)
    if t == "GROUP_ROLE_REVOKE":
        return _apply_group_role_revoke(state, env)
    if t == "GROUP_MEMBERSHIP_REQUEST":
        return _apply_group_membership_request(state, env)
    if t == "GROUP_MEMBERSHIP_DECIDE":
        return _apply_group_membership_decide(state, env)
    if t == "GROUP_MEMBERSHIP_REMOVE":
        return _apply_group_membership_remove(state, env)
    if t == "GROUP_SIGNERS_SET":
        return _apply_group_signers_set(state, env)
    if t == "GROUP_MODERATORS_SET":
        return _apply_group_moderators_set(state, env)

    # Treasury subset
    if t == "GROUP_TREASURY_CREATE":
        return _apply_group_treasury_create(state, env)
    if t == "GROUP_TREASURY_SPEND_PROPOSE":
        return _apply_group_treasury_spend_propose(state, env)
    if t == "GROUP_TREASURY_SPEND_SIGN":
        return _apply_group_treasury_spend_sign(state, env)
    if t == "GROUP_TREASURY_SPEND_CANCEL":
        return _apply_group_treasury_spend_cancel(state, env)
    if t == "GROUP_TREASURY_SPEND_EXECUTE":
        return _apply_group_treasury_spend_execute(state, env)
    if t == "GROUP_TREASURY_POLICY_SET":
        return _apply_group_treasury_policy_set(state, env)
    if t == "GROUP_TREASURY_SPEND_EXPIRE":
        return _apply_group_treasury_spend_expire(state, env)

    # Audit anchor (if present in canon) — claim it even if MVP stores nothing.
    if t == "GROUP_TREASURY_AUDIT_ANCHOR_SET":
        return {"applied": "GROUP_TREASURY_AUDIT_ANCHOR_SET"}

    return None


__all__ = ["GroupsApplyError", "apply_groups"]
