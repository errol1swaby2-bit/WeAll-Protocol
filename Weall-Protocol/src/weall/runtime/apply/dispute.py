# src/weall/runtime/apply/dispute.py
from __future__ import annotations

"""Dispute state transitions.

This module contains deterministic apply semantics for dispute-related tx types.
The legacy router (weall.runtime.domain_apply_all) delegates to `apply_dispute()`
so we can keep the codebase maintainable.

This module raises DisputeApplyError (instead of ApplyError) so it can remain
standalone and not import the legacy monolith. The router translates
DisputeApplyError into ApplyError to preserve error codes and failure semantics.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class DisputeApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _mk_id(prefix: str, env: TxEnvelope, provided: object) -> str:
    s = _as_str(provided).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{env.nonce}"


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise DisputeApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_disputes(state: Json) -> Json:
    return _ensure_root_dict(state, "disputes_by_id")


def _get_dispute(state: Json, dispute_id: str) -> Json:
    disputes = _ensure_disputes(state)
    d = disputes.get(dispute_id)
    if not isinstance(d, dict):
        raise DisputeApplyError("not_found", "dispute_not_found", {"dispute_id": dispute_id})
    return d


def dispute_open(state: Json, env: TxEnvelope) -> Json:
    """Open a dispute. Exposed for other domains (e.g., content escalation)."""
    payload = _as_dict(env.payload)
    dispute_id = _mk_id("dispute", env, payload.get("dispute_id"))
    target_type = _as_str(payload.get("target_type")).strip()
    target_id = _as_str(payload.get("target_id")).strip()
    reason = _as_str(payload.get("reason")).strip()

    if not target_type or not target_id:
        raise DisputeApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})

    disputes = _ensure_disputes(state)
    if dispute_id in disputes:
        raise DisputeApplyError("duplicate", "dispute_id_exists", {"dispute_id": dispute_id})

    disputes[dispute_id] = {
        "id": dispute_id,
        "stage": "open",
        "opened_by": env.signer,
        "opened_at_nonce": int(env.nonce),
        "target_type": target_type,
        "target_id": target_id,
        "reason": reason,
        "evidence": [],
        "jurors": {},
        "votes": {},
        "resolved": False,
        "resolution": None,
        "appeals": [],
    }
    return {"applied": "DISPUTE_OPEN", "dispute_id": dispute_id}


def _apply_dispute_stage_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    stage = _as_str(payload.get("stage")).strip()
    if not dispute_id or not stage:
        raise DisputeApplyError("invalid_payload", "missing_dispute_or_stage", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    d["stage"] = stage
    d["stage_set_at_nonce"] = int(env.nonce)
    return {"applied": "DISPUTE_STAGE_SET", "dispute_id": dispute_id, "stage": stage}


def _apply_dispute_evidence_declare(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    eid = _mk_id("evidence", env, payload.get("evidence_id"))
    entry = {
        "id": eid,
        "declared_by": env.signer,
        "declared_at_nonce": int(env.nonce),
        "kind": _as_str(payload.get("kind")).strip(),
        "cid": _as_str(payload.get("cid")).strip(),
        "meta": payload.get("meta") if isinstance(payload.get("meta"), dict) else {},
        "bound": False,
    }
    ev = d.get("evidence")
    if not isinstance(ev, list):
        ev = []
    ev.append(entry)
    d["evidence"] = ev
    return {"applied": "DISPUTE_EVIDENCE_DECLARE", "dispute_id": dispute_id, "evidence_id": eid}


def _apply_dispute_evidence_bind(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    evidence_id = _as_str(payload.get("evidence_id")).strip()
    if not dispute_id or not evidence_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_or_evidence_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    ev = d.get("evidence")
    if not isinstance(ev, list):
        ev = []
    for e in ev:
        if isinstance(e, dict) and e.get("id") == evidence_id:
            e["bound"] = True
            e["bound_at_nonce"] = int(env.nonce)
            e["bound_by"] = env.signer
            break
    else:
        raise DisputeApplyError("not_found", "evidence_not_found", {"evidence_id": evidence_id})
    d["evidence"] = ev
    return {"applied": "DISPUTE_EVIDENCE_BIND", "dispute_id": dispute_id, "evidence_id": evidence_id}


def _apply_dispute_juror_assign(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    juror = _as_str(payload.get("juror") or payload.get("juror_id")).strip()
    if not dispute_id or not juror:
        raise DisputeApplyError("invalid_payload", "missing_dispute_or_juror", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    jurors[juror] = {"status": "assigned", "assigned_at_nonce": int(env.nonce)}
    d["jurors"] = jurors
    return {"applied": "DISPUTE_JUROR_ASSIGN", "dispute_id": dispute_id, "juror": juror}


def _apply_dispute_juror_accept(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    j = jurors.get(env.signer)
    if not isinstance(j, dict):
        j = {"status": "assigned"}
    j["status"] = "accepted"
    j["accepted_at_nonce"] = int(env.nonce)
    jurors[env.signer] = j
    d["jurors"] = jurors
    return {"applied": "DISPUTE_JUROR_ACCEPT", "dispute_id": dispute_id}


def _apply_dispute_juror_decline(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    j = jurors.get(env.signer)
    if not isinstance(j, dict):
        j = {"status": "assigned"}
    j["status"] = "declined"
    j["declined_at_nonce"] = int(env.nonce)
    jurors[env.signer] = j
    d["jurors"] = jurors
    return {"applied": "DISPUTE_JUROR_DECLINE", "dispute_id": dispute_id}


def _apply_dispute_juror_attendance(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    present = payload.get("present")
    present = True if present is None else bool(present)
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    j = jurors.get(env.signer)
    if not isinstance(j, dict):
        j = {"status": "accepted"}
    j["attendance"] = {"present": present, "at_nonce": int(env.nonce)}
    jurors[env.signer] = j
    d["jurors"] = jurors
    return {"applied": "DISPUTE_JUROR_ATTENDANCE", "dispute_id": dispute_id, "present": present}


def _apply_dispute_vote_submit(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    votes = d.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    votes[env.signer] = {"vote": payload.get("vote"), "at_nonce": int(env.nonce)}
    d["votes"] = votes

    # Optional MVP auto-resolution trigger:
    # If the juror submits a resolution object, we enqueue the canonical receipt-only
    # DISPUTE_RESOLVE (parent=DISPUTE_VOTE_SUBMIT) as a SYSTEM tx.
    #
    # NOTE: We do not have the canonical tx_id in apply-space, so we use a stable
    # deterministic reference as the parent pointer. Receipt-only admission only
    # requires that a parent exists.
    resolution = payload.get("resolution")
    if isinstance(resolution, dict) and resolution:
        height = int(state.get("height", 0) or 0)
        due_height = height + 1
        parent_ref = f"tx:{env.signer}:{int(env.nonce)}"

        enqueue_system_tx(
            state,
            tx_type="DISPUTE_RESOLVE",
            payload={
                "dispute_id": dispute_id,
                "resolution": resolution,
                "_parent_ref": parent_ref,
            },
            due_height=due_height,
            signer="SYSTEM",
            once=True,
            parent=parent_ref,
            phase="post",
        )

    return {"applied": "DISPUTE_VOTE_SUBMIT", "dispute_id": dispute_id}


def _apply_dispute_resolve(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    d["resolved"] = True
    d["stage"] = "resolved"
    d["resolution"] = payload.get("resolution")
    d["resolved_at_nonce"] = int(env.nonce)

    # Enqueue follow-up enforcement receipts/actions.
    # Canon says DISPUTE_FINAL_RECEIPT and several enforcement txs have parent=DISPUTE_RESOLVE.
    # We schedule these for the *next* height after this receipt to keep the executor
    # deterministic without requiring a second post-phase emission pass.
    base_due = payload.get("_due_height")
    try:
        base_due_h = int(base_due)
    except Exception:
        # Fallback: assume this receipt is being applied in the next block.
        base_due_h = int(state.get("height", 0) or 0) + 1

    due_height = base_due_h + 1

    # Use the queue item id as a stable "parent" reference if available.
    # (We don't have chain_id here, so we can't compute canonical tx_id.)
    parent_ref = _as_str(payload.get("_system_queue_id") or "").strip() or f"tx:{env.signer}:{int(env.nonce)}"

    # 1) Always emit DISPUTE_FINAL_RECEIPT for audits.
    enqueue_system_tx(
        state,
        tx_type="DISPUTE_FINAL_RECEIPT",
        payload={"dispute_id": dispute_id, "resolution": payload.get("resolution") or {}, "_parent_ref": parent_ref},
        due_height=due_height,
        signer="SYSTEM",
        once=True,
        parent=parent_ref,
        phase="post",
        )

    # 2) Optional enforcement actions (best-effort, schema-light MVP).
    res = payload.get("resolution")
    if isinstance(res, dict):
        actions = res.get("actions")
        if isinstance(actions, list):
            for a in actions:
                if not isinstance(a, dict):
                    continue
                tx_type = _as_str(a.get("tx_type") or "").strip()
                pl = a.get("payload") if isinstance(a.get("payload"), dict) else {}
                if not tx_type:
                    continue
                enqueue_system_tx(
                    state,
                    tx_type=tx_type,
                    payload=dict(pl),
                    due_height=due_height,
                    signer="SYSTEM",
                    once=True,
                    parent=parent_ref,
                    phase="post",
                )

    return {"applied": "DISPUTE_RESOLVE", "dispute_id": dispute_id}


def _apply_dispute_appeal(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    appeals = d.get("appeals")
    if not isinstance(appeals, list):
        appeals = []
    appeals.append({"by": env.signer, "at_nonce": int(env.nonce), "payload": payload})
    d["appeals"] = appeals
    d["stage"] = "appealed"
    return {"applied": "DISPUTE_APPEAL", "dispute_id": dispute_id}


def _apply_dispute_final_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    # Keep a light receipt surface for audits
    root = _ensure_root_dict(state, "dispute_receipts")
    rid = _mk_id("receipt", env, payload.get("receipt_id") or payload.get("id"))
    if rid not in root:
        root[rid] = {"receipt_id": rid, "tx_type": str(env.tx_type or ""), "at_nonce": int(env.nonce), "payload": payload}
    return {"applied": "DISPUTE_FINAL_RECEIPT", "receipt_id": rid, "receipt": True}


def _ensure_cases(state: Json) -> Json:
    cases = state.get("cases")
    if not isinstance(cases, dict):
        cases = {}
        state["cases"] = cases
    if not isinstance(cases.get("types"), dict):
        cases["types"] = {}
    if not isinstance(cases.get("bindings"), dict):
        cases["bindings"] = {}
    if not isinstance(cases.get("outcomes"), list):
        cases["outcomes"] = []
    return cases


def _apply_case_receipt(state: Json, env: TxEnvelope) -> Json:
    """Record case receipts. System-only."""
    _require_system_env(env)
    payload = _as_dict(env.payload)
    cases = _ensure_cases(state)
    t = str(env.tx_type or "").strip()

    if t == "CASE_TYPE_REGISTER":
        case_type = _as_str(payload.get("case_type") or payload.get("type") or payload.get("name")).strip()
        if not case_type:
            raise DisputeApplyError("invalid_payload", "missing_case_type", {"tx_type": t})
        types = cases["types"]
        if case_type not in types:
            types[case_type] = {"case_type": case_type, "registered_at_nonce": int(env.nonce), "payload": payload}
        return {"applied": t, "case_type": case_type, "receipt": True}

    if t == "CASE_BIND_TO_DISPUTE":
        case_id = _as_str(payload.get("case_id") or payload.get("id")).strip() or f"case:{env.nonce}"
        dispute_id = _as_str(payload.get("dispute_id")).strip()
        if not dispute_id:
            raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": t})
        bindings = cases["bindings"]
        if case_id not in bindings:
            bindings[case_id] = {
                "case_id": case_id,
                "dispute_id": dispute_id,
                "bound_at_nonce": int(env.nonce),
                "payload": payload,
            }
        return {"applied": t, "case_id": case_id, "dispute_id": dispute_id, "receipt": True}

    if t == "CASE_OUTCOME_RECEIPT":
        entry = {"tx_type": t, "at_nonce": int(env.nonce), "payload": payload}
        cases["outcomes"].append(entry)
        return {"applied": t, "receipt": True}

    raise DisputeApplyError("tx_unimplemented", "case_tx_not_implemented", {"tx_type": t})


DISPUTE_TX_TYPES: Set[str] = {
    "DISPUTE_OPEN",
    "DISPUTE_STAGE_SET",
    "DISPUTE_EVIDENCE_DECLARE",
    "DISPUTE_EVIDENCE_BIND",
    "DISPUTE_JUROR_ASSIGN",
    "DISPUTE_JUROR_ACCEPT",
    "DISPUTE_JUROR_DECLINE",
    "DISPUTE_JUROR_ATTENDANCE",
    "DISPUTE_VOTE_SUBMIT",
    "DISPUTE_RESOLVE",
    "DISPUTE_APPEAL",
    "DISPUTE_FINAL_RECEIPT",
    # Cases (canon: receipt-only, block context)
    "CASE_TYPE_REGISTER",
    "CASE_BIND_TO_DISPUTE",
    "CASE_OUTCOME_RECEIPT",
}


def apply_dispute(state: Json, env: TxEnvelope) -> Optional[Json]:
    """Apply dispute txs. Returns meta dict if handled; otherwise None."""
    t = str(env.tx_type or "").strip()
    if t not in DISPUTE_TX_TYPES:
        return None

    if t == "DISPUTE_OPEN":
        return dispute_open(state, env)
    if t == "DISPUTE_STAGE_SET":
        return _apply_dispute_stage_set(state, env)
    if t == "DISPUTE_EVIDENCE_DECLARE":
        return _apply_dispute_evidence_declare(state, env)
    if t == "DISPUTE_EVIDENCE_BIND":
        return _apply_dispute_evidence_bind(state, env)
    if t == "DISPUTE_JUROR_ASSIGN":
        return _apply_dispute_juror_assign(state, env)
    if t == "DISPUTE_JUROR_ACCEPT":
        return _apply_dispute_juror_accept(state, env)
    if t == "DISPUTE_JUROR_DECLINE":
        return _apply_dispute_juror_decline(state, env)
    if t == "DISPUTE_JUROR_ATTENDANCE":
        return _apply_dispute_juror_attendance(state, env)
    if t == "DISPUTE_VOTE_SUBMIT":
        return _apply_dispute_vote_submit(state, env)
    if t == "DISPUTE_RESOLVE":
        return _apply_dispute_resolve(state, env)
    if t == "DISPUTE_APPEAL":
        return _apply_dispute_appeal(state, env)
    if t == "DISPUTE_FINAL_RECEIPT":
        return _apply_dispute_final_receipt(state, env)

    if t in {"CASE_TYPE_REGISTER", "CASE_BIND_TO_DISPUTE", "CASE_OUTCOME_RECEIPT"}:
        return _apply_case_receipt(state, env)

    return None
