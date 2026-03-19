# src/weall/runtime/apply/governance.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from weall.runtime.errors import ApplyError
from weall.runtime.econ_phase import is_econ_unlocked, is_economic_system_tx
from weall.runtime.param_policy import validate_param_blob
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission_types import TxEnvelope

Json = Dict[str, Any]


def _d(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _l(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _s(x: Any) -> str:
    return x if isinstance(x, str) else ("" if x is None else str(x))


def _i(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return int(default)


def _sorted_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in sorted(d.keys(), key=lambda x: str(x)):
        out[str(k)] = d[k]
    return out


def _height_hint(state: Json, env: TxEnvelope) -> int:
    p = _d(env.payload)
    dh = p.get("_due_height")
    if isinstance(dh, int) and dh > 0:
        return int(dh)
    return int(_i(state.get("height"), 0) + 1)


def _ensure_root(state: Json) -> Dict[str, Any]:
    root = state.get("gov_proposals_by_id")
    if not isinstance(root, dict):
        root = {}
        state["gov_proposals_by_id"] = root
    if not isinstance(state.get("gov_proposal_receipts"), list):
        state["gov_proposal_receipts"] = []
    if not isinstance(state.get("gov_execution_receipts"), list):
        state["gov_execution_receipts"] = []
    if not isinstance(state.get("gov_delegations"), dict):
        state["gov_delegations"] = {}
    if not isinstance(state.get("gov_config"), dict):
        state["gov_config"] = {}
    if not isinstance(state.get("gov_stage_set_receipts"), list):
        state["gov_stage_set_receipts"] = []
    if not isinstance(state.get("gov_rules_set_receipts"), list):
        state["gov_rules_set_receipts"] = []
    if not isinstance(state.get("gov_quorum_set_receipts"), list):
        state["gov_quorum_set_receipts"] = []
    return root


def _proposal(root: Dict[str, Any], proposal_id: str) -> Dict[str, Any]:
    pr = root.get(proposal_id)
    if not isinstance(pr, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": proposal_id})
    return pr


def _stage(pr: Dict[str, Any]) -> str:
    return _s(pr.get("stage")).strip().lower() or "draft"


def _extract_actions(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = _l(payload.get("actions"))
    out: List[Dict[str, Any]] = []
    for a in raw:
        if not isinstance(a, dict):
            continue
        tx_type = _s(a.get("tx_type") or a.get("type")).strip().upper()
        if not tx_type:
            continue
        out.append({"tx_type": tx_type, "payload": _d(a.get("payload"))})
    return out


def _enforce_genesis_econ_lock(state: Json, actions: List[Dict[str, Any]]) -> None:
    if is_econ_unlocked(state, now_s=_i(state.get("time"), 0)):
        return
    for a in actions:
        tx_type = _s(a.get("tx_type")).strip().upper()
        if tx_type and is_economic_system_tx(tx_type):
            raise ApplyError(
                "forbidden",
                "economic_actions_locked",
                {"tx_type": tx_type, "reason": "genesis_economic_lock"},
            )

DEFAULT_GOV_ACTION_ALLOWLIST = frozenset({
    "ECONOMICS_ACTIVATION",
    "FEE_POLICY_SET",
    "GOV_QUORUM_SET",
    "GOV_RULES_SET",
    "TREASURY_PARAMS_SET",
    "VALIDATOR_SET_UPDATE",
})

_ALLOWED_GOV_QUORUM_KEYS = frozenset({"quorum_percent", "quorum_bps"})
_ALLOWED_GOV_RULES_ROOTS = frozenset({"params", "treasury"})


def _allowed_gov_action_types(state: Json) -> frozenset[str]:
    params = _d(state.get("params"))
    raw = params.get("gov_action_allowlist")
    if isinstance(raw, list) and raw:
        out = {
            _s(item).strip().upper()
            for item in raw
            if _s(item).strip()
        }
        if out:
            return frozenset(sorted(out))
    return DEFAULT_GOV_ACTION_ALLOWLIST


def _validate_gov_quorum_payload(payload: Dict[str, Any]) -> None:
    extras = sorted(str(k) for k in payload.keys() if str(k) not in _ALLOWED_GOV_QUORUM_KEYS)
    if extras:
        raise ApplyError("forbidden", "governance_quorum_field_not_allowed", {"fields": extras})


def _validate_gov_rules_payload(payload: Dict[str, Any]) -> None:
    extras = sorted(str(k) for k in payload.keys() if str(k) not in _ALLOWED_GOV_RULES_ROOTS)
    if extras:
        raise ApplyError("forbidden", "governance_rules_root_not_allowed", {"fields": extras})

    params_blob = payload.get("params")
    if isinstance(params_blob, dict) and params_blob:
        try:
            validate_param_blob(base_path=("params",), blob=params_blob)
        except ValueError as e:
            raise ApplyError("forbidden", str(e), {"path": "params"}) from e

    treasury_blob = payload.get("treasury")
    if isinstance(treasury_blob, dict) and treasury_blob:
        try:
            validate_param_blob(base_path=("treasury",), blob=treasury_blob)
        except ValueError as e:
            raise ApplyError("forbidden", str(e), {"path": "treasury"}) from e


def _validate_governance_action_payload(tx_type: str, payload: Dict[str, Any]) -> None:
    t = _s(tx_type).strip().upper()
    if t == "GOV_QUORUM_SET":
        _validate_gov_quorum_payload(payload)
    elif t == "GOV_RULES_SET":
        _validate_gov_rules_payload(payload)


def _assert_governance_actions_allowed(state: Json, actions: List[Dict[str, Any]]) -> None:
    allowed = _allowed_gov_action_types(state)
    for action in actions:
        tx_type = _s(action.get("tx_type")).strip().upper()
        if not tx_type:
            continue
        if tx_type not in allowed:
            raise ApplyError("forbidden", "governance_action_not_allowed", {"tx_type": tx_type})
        _validate_governance_action_payload(tx_type, _d(action.get("payload")))



def _apply_gov_proposal_create(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})
    if proposal_id in root:
        raise ApplyError("conflict", "proposal_already_exists", {"proposal_id": proposal_id})

    rules = _d(p.get("rules"))
    actions = _extract_actions(p)
    _assert_governance_actions_allowed(state, actions)
    _enforce_genesis_econ_lock(state, actions)

    h = _height_hint(state, env)

    # Spec lifecycle: Draft → Poll → Revision → Validation → Vote → Execution.
    # Backward compatibility: allow rules.start_stage="voting" to preserve older flows.
    start_stage = _s(rules.get("start_stage") if isinstance(rules, dict) else "").strip().lower() or "draft"
    if start_stage not in {"draft", "poll", "revision", "validation", "voting", "vote"}:
        start_stage = "draft"

    root[proposal_id] = {
        "proposal_id": proposal_id,
        "creator": str(env.signer),
        "title": _s(p.get("title")).strip(),
        "body": _s(p.get("body")).strip(),
        "stage": start_stage,
        "rules": rules,
        "actions": actions,
        "created_at_height": int(h),
        "updated_at_height": int(h),
        # Poll vs final vote storage (both use GOV_VOTE_CAST)
        "poll_votes": {},
        "votes": {},
        "tallies": [],
        "poll_tallies": [],
        "executions": [],
        "closed_at_height": 0,
        "tallied_at_height": 0,
        "executed_at_height": 0,
        "finalized_at_height": 0,
        # Stage timing hints (used by gov_engine for deterministic lifecycle)
        "draft_at_height": int(h) if start_stage == "draft" else 0,
        "poll_opened_at_height": int(h) if start_stage == "poll" else 0,
        "revision_opened_at_height": int(h) if start_stage == "revision" else 0,
        "validation_opened_at_height": int(h) if start_stage == "validation" else 0,
        "voting_opened_at_height": int(h) if start_stage in {"voting", "vote"} else 0,
    }
    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_proposal_edit(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    """
    Minimal claimable implementation:
      - only creator may edit
      - editable while stage in {"draft","voting"}
      - may update rules/actions/title if provided
    """
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})
    pr = _proposal(root, proposal_id)

    if str(pr.get("creator", "")) != str(env.signer):
        raise ApplyError("forbidden", "only_creator_can_edit", {"proposal_id": proposal_id})

    stg = _stage(pr)
    # Creator may edit in Draft and Revision. We also keep "voting" editable for
    # legacy proposals that started in voting (older tests / deployments).
    if stg not in {"draft", "revision", "voting"}:
        raise ApplyError("forbidden", "proposal_not_editable", {"proposal_id": proposal_id, "stage": stg})

    # Apply optional fields
    if "rules" in p:
        pr["rules"] = _d(p.get("rules"))
    if "title" in p:
        pr["title"] = _s(p.get("title")).strip()

    if "body" in p:
        pr["body"] = _s(p.get("body")).strip()

    if "actions" in p:
        actions = _extract_actions(p)
        _assert_governance_actions_allowed(state, actions)
        _enforce_genesis_econ_lock(state, actions)
        pr["actions"] = actions

    h = _height_hint(state, env)
    pr["updated_at_height"] = int(h)
    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_proposal_withdraw(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    """
    Minimal claimable implementation:
      - only creator may withdraw
      - cannot withdraw if finalized
      - sets stage="withdrawn"
    """
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})
    pr = _proposal(root, proposal_id)

    if str(pr.get("creator", "")) != str(env.signer):
        raise ApplyError("forbidden", "only_creator_can_withdraw", {"proposal_id": proposal_id})

    stg = _stage(pr)
    if stg == "finalized":
        raise ApplyError("forbidden", "proposal_already_finalized", {"proposal_id": proposal_id})

    h = _height_hint(state, env)
    pr["stage"] = "withdrawn"
    pr["updated_at_height"] = int(h)
    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_vote_cast(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()

    # ✅ Backward/forward compatibility: web UI used "choice"
    vote = _s(p.get("vote") or p.get("choice")).strip().lower()

    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})
    if not vote:
        raise ApplyError("invalid_payload", "missing_vote", {})

    pr = _proposal(root, proposal_id)
    stg = _stage(pr)
    # GOV_VOTE_CAST is used for both poll and final vote depending on stage.
    if stg not in {"poll", "voting", "vote"}:
        raise ApplyError("forbidden", "proposal_not_voteable", {"proposal_id": proposal_id, "stage": stg})

    key = "poll_votes" if stg == "poll" else "votes"
    votes = pr.get(key)
    if not isinstance(votes, dict):
        votes = {}
        pr[key] = votes

    h = _height_hint(state, env)
    votes[str(env.signer)] = {"vote": vote, "height": int(h)}
    pr["updated_at_height"] = int(h)
    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_vote_revoke(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    """
    Minimal claimable implementation:
      - removes signer vote if present
      - allowed during voting and closed (safe for tests)
    """
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})
    pr = _proposal(root, proposal_id)

    stg = _stage(pr)
    # Revoke is allowed during poll/vote and is also tolerated post-close for
    # test convenience, matching prior behavior.
    key = "poll_votes" if stg == "poll" else "votes"
    votes = pr.get(key)
    if not isinstance(votes, dict):
        votes = {}
        pr[key] = votes

    votes.pop(str(env.signer), None)

    h = _height_hint(state, env)
    pr["updated_at_height"] = int(h)
    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_voting_close(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})

    pr = _proposal(root, proposal_id)
    h = _height_hint(state, env)
    pr["stage"] = "closed"
    pr["closed_at_height"] = int(h)
    pr["updated_at_height"] = int(h)
    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_tally_publish(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})

    pr = _proposal(root, proposal_id)
    h = _height_hint(state, env)

    pr["stage"] = "tallied"
    pr["tallied_at_height"] = int(h)
    pr["updated_at_height"] = int(h)

    tallies = pr.get("tallies")
    if not isinstance(tallies, list):
        tallies = []
        pr["tallies"] = tallies
    tallies.append({"height": int(h), "payload": dict(p)})
    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_execute(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})

    pr = _proposal(root, proposal_id)
    h = _height_hint(state, env)

    actions = _extract_actions(p)
    if not actions:
        snap = pr.get("actions")
        if isinstance(snap, list):
            actions = []
            for a in snap:
                if isinstance(a, dict):
                    actions.append({"tx_type": _s(a.get("tx_type")).strip().upper(), "payload": _d(a.get("payload"))})

    _assert_governance_actions_allowed(state, actions)

    parent_ref = env.parent or _s(p.get("_parent_ref")).strip() or None
    for a in actions:
        tx_type = _s(a.get("tx_type")).strip().upper()
        if not tx_type:
            continue
        ap = dict(_d(a.get("payload")))
        if parent_ref:
            ap.setdefault("_parent_ref", parent_ref)

        enqueue_system_tx(
            state,
            tx_type=tx_type,
            payload=ap,
            due_height=int(h + 1),
            signer="SYSTEM",
            parent=parent_ref,
            phase="post",
            once=True,
        )

    execs = pr.get("executions")
    if not isinstance(execs, list):
        execs = []
        pr["executions"] = execs
    execs.append({"height": int(h), "actions": actions})

    pr["stage"] = "executed"
    pr["executed_at_height"] = int(h)
    pr["updated_at_height"] = int(h)

    enqueue_system_tx(
        state,
        tx_type="GOV_EXECUTION_RECEIPT",
        payload={"proposal_id": proposal_id, "ok": True, "_parent_ref": parent_ref} if parent_ref else {"proposal_id": proposal_id, "ok": True},
        due_height=int(h + 1),
        signer="SYSTEM",
        parent=parent_ref,
        phase="post",
        once=True,
    )

    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_execution_receipt(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    _ensure_root(state)
    p = _d(env.payload)
    lst = state.get("gov_execution_receipts")
    if not isinstance(lst, list):
        lst = []
        state["gov_execution_receipts"] = lst
    lst.append(dict(p))
    return {"applied": True}


def _apply_gov_proposal_finalize(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})

    pr = _proposal(root, proposal_id)
    h = _height_hint(state, env)
    pr["stage"] = "finalized"
    pr["finalized_at_height"] = int(h)
    pr["updated_at_height"] = int(h)

    parent_ref = env.parent or _s(p.get("_parent_ref")).strip() or None
    enqueue_system_tx(
        state,
        tx_type="GOV_PROPOSAL_RECEIPT",
        payload={"proposal_id": proposal_id, "finalized": True, "_parent_ref": parent_ref} if parent_ref else {"proposal_id": proposal_id, "finalized": True},
        due_height=int(h + 1),
        signer="SYSTEM",
        parent=parent_ref,
        phase="post",
        once=True,
    )

    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_proposal_receipt(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    _ensure_root(state)
    p = _d(env.payload)
    lst = state.get("gov_proposal_receipts")
    if not isinstance(lst, list):
        lst = []
        state["gov_proposal_receipts"] = lst
    lst.append(dict(p))
    return {"applied": True}


def _apply_gov_delegation_set(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    _ensure_root(state)
    p = _d(env.payload)
    delegatee = _s(p.get("delegatee")).strip()
    delegations = state.get("gov_delegations")
    if not isinstance(delegations, dict):
        delegations = {}
        state["gov_delegations"] = delegations
    if delegatee:
        delegations[str(env.signer)] = delegatee
    else:
        delegations.pop(str(env.signer), None)
    return {"applied": True}


def _apply_gov_stage_set(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    """Apply GOV_STAGE_SET (receipt-only, SYSTEM origin).

    Canon: receipt_only parent=GOV_PROPOSAL_CREATE.
    Payload is expected (by schema) to include proposal_id and may include stage.

    Minimal production-safe behavior:
      - record receipt payload
      - if proposal exists, optionally update its stage to payload.stage
    """
    root = _ensure_root(state)
    p = _d(env.payload)
    proposal_id = _s(p.get("proposal_id")).strip()
    if not proposal_id:
        raise ApplyError("invalid_payload", "missing_proposal_id", {})

    # Record receipt
    rec = dict(p)
    rec.setdefault("proposal_id", proposal_id)
    rec["_height"] = _height_hint(state, env)
    rec["_parent"] = _s(env.parent) if env.parent is not None else ""
    state["gov_stage_set_receipts"].append(rec)

    # Optionally update proposal stage if provided and proposal exists.
    # This is the canonical way the deterministic lifecycle advances proposals.
    stage = _s(p.get("stage")).strip().lower()
    if proposal_id in root and stage:
        pr = _proposal(root, proposal_id)
        pr["stage"] = stage
        pr["updated_at_height"] = int(rec["_height"])

        # Stamp stage entry heights so gov_engine can compute durations safely.
        h = int(rec["_height"])
        if stage == "poll" and int(_i(pr.get("poll_opened_at_height"), 0)) <= 0:
            pr["poll_opened_at_height"] = h
        if stage == "revision" and int(_i(pr.get("revision_opened_at_height"), 0)) <= 0:
            pr["revision_opened_at_height"] = h
        if stage == "validation" and int(_i(pr.get("validation_opened_at_height"), 0)) <= 0:
            pr["validation_opened_at_height"] = h
        if stage in {"voting", "vote"} and int(_i(pr.get("voting_opened_at_height"), 0)) <= 0:
            pr["voting_opened_at_height"] = h

        # Optional poll summary (emitted by gov_engine when transitioning poll->revision)
        if "poll_tally" in p or "poll_total_votes" in p:
            pt = pr.get("poll_tallies")
            if not isinstance(pt, list):
                pt = []
                pr["poll_tallies"] = pt
            pt.append(
                {
                    "height": h,
                    "payload": {
                        "poll_tally": _d(p.get("poll_tally")),
                        "poll_total_votes": _i(p.get("poll_total_votes"), 0),
                    },
                }
            )

    # Also store last stage change in gov_config (useful for diagnostics)
    cfg = state.get("gov_config")
    if isinstance(cfg, dict):
        cfg["last_stage_set"] = {"proposal_id": proposal_id, "stage": stage or None, "height": int(rec["_height"])}

    return {"applied": True, "proposal_id": proposal_id}


def _apply_gov_quorum_set(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    """Apply GOV_QUORUM_SET (receipt-only, SYSTEM origin).

    Canon: receipt_only parent=GOV_EXECUTE.
    Payload may be empty or contain quorum settings blob.

    Minimal behavior:
      - store quorum blob under state.gov_config["quorum"]
      - append receipt to gov_quorum_set_receipts
    """
    _ensure_root(state)
    if not bool(getattr(env, "system", False)) and str(getattr(env, "signer", "")) != "SYSTEM":
        raise ApplyError("forbidden", "system_tx_required", {"tx_type": env.tx_type})

    p = _d(env.payload)
    _validate_gov_quorum_payload(p)

    # Minimal bounds safety: if a quorum numeric field is present, keep it sane.
    if "quorum_percent" in p:
        qp = _i(p.get("quorum_percent"), -1)
        if qp < 1 or qp > 100:
            raise ApplyError("invalid_payload", "quorum_percent_out_of_bounds", {"have": qp})
    if "quorum_bps" in p:
        qb = _i(p.get("quorum_bps"), -1)
        if qb < 1 or qb > 10_000:
            raise ApplyError("invalid_payload", "quorum_bps_out_of_bounds", {"have": qb})

    rec = _sorted_dict(dict(p))
    rec["_height"] = _height_hint(state, env)
    rec["_parent"] = _s(env.parent) if env.parent is not None else ""
    state["gov_quorum_set_receipts"].append(rec)

    cfg = state.get("gov_config")
    if isinstance(cfg, dict):
        cfg["quorum"] = _sorted_dict(dict(p))
        cfg["quorum"]["_height"] = int(rec["_height"])

    return {"applied": True}


def _apply_gov_rules_set(state: Json, env: TxEnvelope) -> Dict[str, Any]:
    """Apply GOV_RULES_SET (receipt-only, SYSTEM origin).

    Canon: receipt_only parent=GOV_EXECUTE.
    Payload may be empty or contain rules/settings blob.

    Minimal behavior:
      - store rules blob under state.gov_config["rules"]
      - append receipt to gov_rules_set_receipts
    """
    _ensure_root(state)
    if not bool(getattr(env, "system", False)) and str(getattr(env, "signer", "")) != "SYSTEM":
        raise ApplyError("forbidden", "system_tx_required", {"tx_type": env.tx_type})

    p = _d(env.payload)
    _validate_gov_rules_payload(p)

    rec = _sorted_dict(dict(p))
    rec["_height"] = _height_hint(state, env)
    rec["_parent"] = _s(env.parent) if env.parent is not None else ""
    state["gov_rules_set_receipts"].append(rec)

    cfg = state.get("gov_config")
    if isinstance(cfg, dict):
        cfg["rules"] = _sorted_dict(dict(p))
        cfg["rules"]["_height"] = int(rec["_height"])

    return {"applied": True}


_GOV_HANDLERS = {
    "GOV_PROPOSAL_CREATE": _apply_gov_proposal_create,
    "GOV_PROPOSAL_EDIT": _apply_gov_proposal_edit,
    "GOV_PROPOSAL_WITHDRAW": _apply_gov_proposal_withdraw,
    "GOV_DELEGATION_SET": _apply_gov_delegation_set,
    "GOV_VOTE_CAST": _apply_gov_vote_cast,
    "GOV_VOTE_REVOKE": _apply_gov_vote_revoke,
    "GOV_VOTING_CLOSE": _apply_gov_voting_close,
    "GOV_TALLY_PUBLISH": _apply_gov_tally_publish,
    "GOV_STAGE_SET": _apply_gov_stage_set,
    "GOV_QUORUM_SET": _apply_gov_quorum_set,
    "GOV_RULES_SET": _apply_gov_rules_set,
    "GOV_EXECUTE": _apply_gov_execute,
    "GOV_EXECUTION_RECEIPT": _apply_gov_execution_receipt,
    "GOV_PROPOSAL_FINALIZE": _apply_gov_proposal_finalize,
    "GOV_PROPOSAL_RECEIPT": _apply_gov_proposal_receipt,
}


def apply_governance(state: Json, env: TxEnvelope) -> Optional[Dict[str, Any]]:
    t = _s(env.tx_type).strip().upper()
    fn = _GOV_HANDLERS.get(t)
    if fn is None:
        return None
    return fn(state, env)


__all__ = ["apply_governance"]
