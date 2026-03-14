#!/usr/bin/env python3
"""
Patch domain_apply.py to implement and wire the remaining canon tx types.

This script:
- Inserts deterministic MVP semantics for txs currently routed to _apply_canon_missing(...)
- Rewires apply_tx dispatch branches to call the new functions
- Rewires some txs to existing helpers already present in domain_apply.py
"""

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_APPLY = REPO_ROOT / "src" / "weall" / "runtime" / "domain_apply.py"


INSERT_MARKER_BEGIN = "# BEGIN WEALL REMAINING CANON TXS (AUTO-GENERATED)\n"
INSERT_MARKER_END = "# END WEALL REMAINING CANON TXS (AUTO-GENERATED)\n"


INSERT_BLOCK = r'''# BEGIN WEALL REMAINING CANON TXS (AUTO-GENERATED)
# These tx apply semantics are deterministic MVP implementations for canon txs
# that previously routed to _apply_canon_missing(...). They are intentionally
# conservative: never delete history, always prefer stable ids, and store data
# in explicit state roots.

def _ensure_root_dict(state: Json, key: str) -> Json:
    return _ensure_dict_root(state, key)


def _ensure_root_list(state: Json, key: str) -> list:
    return _ensure_list_root(state, key)


def _mk_id(prefix: str, env: TxEnvelope, provided: object) -> str:
    s = _as_str(provided).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{env.nonce}"


# -----------------------------
# Identity: ban / reinstate
# -----------------------------

def _apply_account_ban(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("account_id") or payload.get("target") or env.signer).strip()
    if not target:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    acct = _create_default_account(state, target)
    acct["banned"] = True
    acct["banned_at_nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_BAN", "account_id": target}


def _apply_account_reinstate(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("account_id") or payload.get("target") or env.signer).strip()
    if not target:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    acct = _create_default_account(state, target)
    acct["banned"] = False
    acct["reinstated_at_nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_REINSTATE", "account_id": target}


# -----------------------------
# Profile / Social graph
# -----------------------------

def _apply_profile_update(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    profiles = _ensure_root_dict(state, "profiles")
    cur = profiles.get(env.signer)
    if not isinstance(cur, dict):
        cur = {"account_id": env.signer}

    # allow common fields; store extras under "meta"
    for k in ("display_name", "bio", "avatar_cid", "website", "location"):
        if k in payload:
            cur[k] = payload.get(k)

    meta = cur.get("meta")
    if not isinstance(meta, dict):
        meta = {}
    extra = payload.get("meta")
    if isinstance(extra, dict):
        for k, v in extra.items():
            meta[str(k)] = v
    cur["meta"] = meta
    cur["updated_at_nonce"] = int(env.nonce)

    profiles[env.signer] = cur
    return {"applied": "PROFILE_UPDATE", "account_id": env.signer}


def _apply_follow_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("account_id") or payload.get("target")).strip()
    if not target:
        raise ApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})

    enabled = payload.get("enabled")
    if enabled is None:
        enabled = payload.get("follow")
    enabled = bool(enabled)

    if enabled:
        return _apply_follow_add(state, TxEnvelope(tx_type="FOLLOW_ADD", signer=env.signer, nonce=env.nonce, payload={"account_id": target}, sig=env.sig, parent=env.parent, system=env.system))
    return _apply_follow_remove(state, TxEnvelope(tx_type="FOLLOW_REMOVE", signer=env.signer, nonce=env.nonce, payload={"account_id": target}, sig=env.sig, parent=env.parent, system=env.system))


def _apply_mute_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("account_id") or payload.get("target")).strip()
    if not target:
        raise ApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})

    enabled = payload.get("enabled")
    if enabled is None:
        enabled = payload.get("mute")
    enabled = bool(enabled)

    if enabled:
        return _apply_mute_add(state, TxEnvelope(tx_type="MUTE_ADD", signer=env.signer, nonce=env.nonce, payload={"account_id": target}, sig=env.sig, parent=env.parent, system=env.system))
    return _apply_mute_remove(state, TxEnvelope(tx_type="MUTE_REMOVE", signer=env.signer, nonce=env.nonce, payload={"account_id": target}, sig=env.sig, parent=env.parent, system=env.system))


# -----------------------------
# Direct Messages (MVP log)
# -----------------------------

def _apply_direct_message_send(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    thread_id = _mk_id("dm", env, payload.get("thread_id"))
    msg_id = _mk_id("dmmsg", env, payload.get("message_id"))

    to = _as_str(payload.get("to")).strip()
    body = _as_str(payload.get("body")).strip()
    if not to or not body:
        raise ApplyError("invalid_payload", "missing_to_or_body", {"tx_type": env.tx_type})

    threads = _ensure_root_dict(state, "dm_threads")
    th = threads.get(thread_id)
    if not isinstance(th, dict):
        th = {"id": thread_id, "participants": sorted({env.signer, to}), "messages": []}

    msgs = th.get("messages")
    if not isinstance(msgs, list):
        msgs = []
    msgs.append(
        {
            "id": msg_id,
            "from": env.signer,
            "to": to,
            "body": body,
            "created_at_nonce": int(env.nonce),
            "redacted": False,
        }
    )
    th["messages"] = msgs
    threads[thread_id] = th
    return {"applied": "DIRECT_MESSAGE_SEND", "thread_id": thread_id, "message_id": msg_id}


def _apply_direct_message_redact(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    thread_id = _as_str(payload.get("thread_id")).strip()
    msg_id = _as_str(payload.get("message_id")).strip()
    if not thread_id or not msg_id:
        raise ApplyError("invalid_payload", "missing_thread_or_message_id", {"tx_type": env.tx_type})

    threads = _ensure_root_dict(state, "dm_threads")
    th = threads.get(thread_id)
    if not isinstance(th, dict):
        raise ApplyError("not_found", "thread_not_found", {"thread_id": thread_id})
    msgs = th.get("messages")
    if not isinstance(msgs, list):
        msgs = []

    for m in msgs:
        if isinstance(m, dict) and m.get("id") == msg_id:
            # only allow sender to redact in MVP
            if m.get("from") != env.signer:
                raise ApplyError("forbidden", "only_sender_can_redact", {"message_id": msg_id})
            m["redacted"] = True
            m["redacted_at_nonce"] = int(env.nonce)
            m["body"] = ""
            break
    else:
        raise ApplyError("not_found", "message_not_found", {"message_id": msg_id})

    th["messages"] = msgs
    threads[thread_id] = th
    return {"applied": "DIRECT_MESSAGE_REDACT", "thread_id": thread_id, "message_id": msg_id}


# -----------------------------
# Disputes (MVP state machine)
# -----------------------------

def _ensure_disputes(state: Json) -> Json:
    return _ensure_root_dict(state, "disputes_by_id")


def _get_dispute(state: Json, dispute_id: str) -> Json:
    disputes = _ensure_disputes(state)
    d = disputes.get(dispute_id)
    if not isinstance(d, dict):
        raise ApplyError("not_found", "dispute_not_found", {"dispute_id": dispute_id})
    return d


def _apply_dispute_open(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _mk_id("dispute", env, payload.get("dispute_id"))
    target_type = _as_str(payload.get("target_type")).strip()
    target_id = _as_str(payload.get("target_id")).strip()
    reason = _as_str(payload.get("reason")).strip()

    if not target_type or not target_id:
        raise ApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})

    disputes = _ensure_disputes(state)
    if dispute_id in disputes:
        raise ApplyError("duplicate", "dispute_id_exists", {"dispute_id": dispute_id})

    disputes[dispute_id] = {
        "id": dispute_id,
        "stage": "open",
        "opened_by": env.signer,
        "opened_at_nonce": int(env.nonce),
        "target_type": target_type,
        "target_id": target_id,
        "reason": reason,
        "evidence": [],
        "jurors": {},    # juror_id -> {status, ...}
        "votes": {},     # juror_id -> vote payload
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
        raise ApplyError("invalid_payload", "missing_dispute_or_stage", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    d["stage"] = stage
    d["stage_set_at_nonce"] = int(env.nonce)
    return {"applied": "DISPUTE_STAGE_SET", "dispute_id": dispute_id, "stage": stage}


def _apply_dispute_evidence_declare(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
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
        raise ApplyError("invalid_payload", "missing_dispute_or_evidence_id", {"tx_type": env.tx_type})
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
        raise ApplyError("not_found", "evidence_not_found", {"evidence_id": evidence_id})
    d["evidence"] = ev
    return {"applied": "DISPUTE_EVIDENCE_BIND", "dispute_id": dispute_id, "evidence_id": evidence_id}


def _apply_dispute_juror_assign(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    juror = _as_str(payload.get("juror") or payload.get("juror_id")).strip()
    if not dispute_id or not juror:
        raise ApplyError("invalid_payload", "missing_dispute_or_juror", {"tx_type": env.tx_type})
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
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
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
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
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
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
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
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    votes = d.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    # store the vote payload (deterministic, no transforms)
    votes[env.signer] = {"vote": payload.get("vote"), "at_nonce": int(env.nonce)}
    d["votes"] = votes
    return {"applied": "DISPUTE_VOTE_SUBMIT", "dispute_id": dispute_id}


def _apply_dispute_resolve(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    d["resolved"] = True
    d["stage"] = "resolved"
    d["resolution"] = payload.get("resolution")
    d["resolved_at_nonce"] = int(env.nonce)
    return {"applied": "DISPUTE_RESOLVE", "dispute_id": dispute_id}


def _apply_dispute_appeal(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    appeals = d.get("appeals")
    if not isinstance(appeals, list):
        appeals = []
    appeals.append({"by": env.signer, "at_nonce": int(env.nonce), "reason": _as_str(payload.get("reason")).strip()})
    d["appeals"] = appeals
    d["stage"] = "appealed"
    return {"applied": "DISPUTE_APPEAL", "dispute_id": dispute_id}


def _apply_dispute_final_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    d["final_receipt"] = {"at_nonce": int(env.nonce), "payload": payload}
    return {"applied": "DISPUTE_FINAL_RECEIPT", "dispute_id": dispute_id}


# -----------------------------
# Content moderation knobs (labels/visibility/lock/escalate)
# -----------------------------

def _get_post_or_comment(state: Json, target_id: str) -> Json:
    posts = state.get("content_posts", {})
    if isinstance(posts, dict) and target_id in posts and isinstance(posts[target_id], dict):
        return posts[target_id]
    comments = state.get("content_comments", {})
    if isinstance(comments, dict) and target_id in comments and isinstance(comments[target_id], dict):
        return comments[target_id]
    raise ApplyError("not_found", "content_not_found", {"target_id": target_id})


def _apply_content_label_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("content_id") or payload.get("target_id")).strip()
    if not target_id:
        raise ApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})
    item = _get_post_or_comment(state, target_id)

    labels = payload.get("labels")
    if isinstance(labels, str):
        labels = [x.strip() for x in labels.split(",") if x.strip()]
    if not isinstance(labels, list):
        labels = []
    # deterministic normalization
    out: list[str] = []
    seen = set()
    for x in labels[:32]:
        s = _as_str(x).strip().lower()
        if not s:
            continue
        if len(s) > 32:
            s = s[:32]
        if s in seen:
            continue
        seen.add(s)
        out.append(s)

    item["labels"] = out
    item["labels_set_at_nonce"] = int(env.nonce)
    return {"applied": "CONTENT_LABEL_SET", "target_id": target_id, "labels": out}


def _apply_content_visibility_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("content_id") or payload.get("target_id")).strip()
    vis = _as_str(payload.get("visibility")).strip().lower()
    if not target_id or not vis:
        raise ApplyError("invalid_payload", "missing_target_or_visibility", {"tx_type": env.tx_type})
    item = _get_post_or_comment(state, target_id)
    item["visibility"] = vis
    item["visibility_set_at_nonce"] = int(env.nonce)
    return {"applied": "CONTENT_VISIBILITY_SET", "target_id": target_id, "visibility": vis}


def _apply_content_thread_lock_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("content_id") or payload.get("target_id")).strip()
    if not target_id:
        raise ApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})
    locked = payload.get("locked")
    locked = True if locked is None else bool(locked)
    item = _get_post_or_comment(state, target_id)
    item["thread_locked"] = locked
    item["thread_lock_set_at_nonce"] = int(env.nonce)
    return {"applied": "CONTENT_THREAD_LOCK_SET", "target_id": target_id, "locked": locked}


def _apply_content_escalate_to_dispute(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("content_id") or payload.get("target_id")).strip()
    if not target_id:
        raise ApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})
    item = _get_post_or_comment(state, target_id)
    # create a dispute referencing this content
    d = _apply_dispute_open(
        state,
        TxEnvelope(
            tx_type="DISPUTE_OPEN",
            signer=env.signer,
            nonce=env.nonce,
            payload={
                "dispute_id": payload.get("dispute_id"),
                "target_type": "content",
                "target_id": target_id,
                "reason": payload.get("reason", "content_escalation"),
            },
            sig=env.sig,
            parent=env.parent,
            system=env.system,
        ),
    )
    item["escalated_dispute_id"] = d.get("dispute_id")
    item["escalated_at_nonce"] = int(env.nonce)
    return {"applied": "CONTENT_ESCALATE_TO_DISPUTE", "target_id": target_id, "dispute_id": d.get("dispute_id")}


def _apply_content_share_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("content_id") or payload.get("target_id")).strip()
    if not target_id:
        raise ApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})
    share_id = _mk_id("share", env, payload.get("share_id"))
    shares = _ensure_root_dict(state, "content_shares")
    if share_id in shares:
        raise ApplyError("duplicate", "share_id_exists", {"share_id": share_id})
    shares[share_id] = {
        "id": share_id,
        "by": env.signer,
        "target_id": target_id,
        "created_at_nonce": int(env.nonce),
        "comment": _as_str(payload.get("comment")).strip(),
    }
    return {"applied": "CONTENT_SHARE_CREATE", "share_id": share_id}


# -----------------------------
# Governance (MVP)
# -----------------------------

def _ensure_gov(state: Json) -> Json:
    return _ensure_root_dict(state, "gov")


def _ensure_proposals(state: Json) -> Json:
    gov = _ensure_gov(state)
    p = gov.get("proposals_by_id")
    if not isinstance(p, dict):
        p = {}
        gov["proposals_by_id"] = p
    return p


def _apply_gov_proposal_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _mk_id("govprop", env, payload.get("proposal_id"))
    proposals = _ensure_proposals(state)
    if pid in proposals:
        raise ApplyError("duplicate", "proposal_id_exists", {"proposal_id": pid})
    proposals[pid] = {
        "id": pid,
        "title": _as_str(payload.get("title")).strip(),
        "body": _as_str(payload.get("body")).strip(),
        "created_by": env.signer,
        "created_at_nonce": int(env.nonce),
        "stage": "draft",
        "withdrawn": False,
        "votes": {},  # account -> {vote, at_nonce}
        "tallies": [],
    }
    return {"applied": "GOV_PROPOSAL_CREATE", "proposal_id": pid}


def _apply_gov_proposal_edit(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_proposal_id", {"tx_type": env.tx_type})
    proposals = _ensure_proposals(state)
    p = proposals.get(pid)
    if not isinstance(p, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    for k in ("title", "body"):
        if k in payload:
            p[k] = _as_str(payload.get(k))
    p["edited_at_nonce"] = int(env.nonce)
    proposals[pid] = p
    return {"applied": "GOV_PROPOSAL_EDIT", "proposal_id": pid}


def _apply_gov_proposal_withdraw(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_proposal_id", {"tx_type": env.tx_type})
    proposals = _ensure_proposals(state)
    p = proposals.get(pid)
    if not isinstance(p, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    p["withdrawn"] = True
    p["withdrawn_at_nonce"] = int(env.nonce)
    proposals[pid] = p
    return {"applied": "GOV_PROPOSAL_WITHDRAW", "proposal_id": pid}


def _apply_gov_stage_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    stage = _as_str(payload.get("stage")).strip()
    if not pid or not stage:
        raise ApplyError("invalid_payload", "missing_proposal_or_stage", {"tx_type": env.tx_type})
    proposals = _ensure_proposals(state)
    p = proposals.get(pid)
    if not isinstance(p, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    p["stage"] = stage
    p["stage_set_at_nonce"] = int(env.nonce)
    proposals[pid] = p
    return {"applied": "GOV_STAGE_SET", "proposal_id": pid, "stage": stage}


def _apply_gov_vote_cast(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_proposal_id", {"tx_type": env.tx_type})
    proposals = _ensure_proposals(state)
    p = proposals.get(pid)
    if not isinstance(p, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    votes = p.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    votes[env.signer] = {"vote": payload.get("vote"), "at_nonce": int(env.nonce)}
    p["votes"] = votes
    proposals[pid] = p
    return {"applied": "GOV_VOTE_CAST", "proposal_id": pid}


def _apply_gov_vote_revoke(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_proposal_id", {"tx_type": env.tx_type})
    proposals = _ensure_proposals(state)
    p = proposals.get(pid)
    if not isinstance(p, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    votes = p.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    votes.pop(env.signer, None)
    p["votes"] = votes
    p["vote_revoked_at_nonce"] = int(env.nonce)
    proposals[pid] = p
    return {"applied": "GOV_VOTE_REVOKE", "proposal_id": pid}


def _apply_gov_delegation_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    delegate = _as_str(payload.get("delegate")).strip()
    if not delegate:
        raise ApplyError("invalid_payload", "missing_delegate", {"tx_type": env.tx_type})
    gov = _ensure_gov(state)
    d = gov.get("delegations")
    if not isinstance(d, dict):
        d = {}
    d[env.signer] = {"delegate": delegate, "at_nonce": int(env.nonce)}
    gov["delegations"] = d
    return {"applied": "GOV_DELEGATION_SET", "account_id": env.signer, "delegate": delegate}


def _apply_gov_quorum_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    gov = _ensure_gov(state)
    gov["quorum"] = payload
    gov["quorum_set_at_nonce"] = int(env.nonce)
    return {"applied": "GOV_QUORUM_SET"}


def _apply_gov_rules_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    gov = _ensure_gov(state)
    gov["rules"] = payload
    gov["rules_set_at_nonce"] = int(env.nonce)
    return {"applied": "GOV_RULES_SET"}


def _apply_gov_execute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    exec_id = _mk_id("govexec", env, payload.get("execution_id"))
    gov = _ensure_gov(state)
    ex = gov.get("executions_by_id")
    if not isinstance(ex, dict):
        ex = {}
    ex[exec_id] = {"id": exec_id, "payload": payload, "at_nonce": int(env.nonce)}
    gov["executions_by_id"] = ex
    return {"applied": "GOV_EXECUTE", "execution_id": exec_id}


def _apply_gov_execution_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    exec_id = _as_str(payload.get("execution_id")).strip()
    if not exec_id:
        raise ApplyError("invalid_payload", "missing_execution_id", {"tx_type": env.tx_type})
    gov = _ensure_gov(state)
    ex = gov.get("executions_by_id")
    if not isinstance(ex, dict) or exec_id not in ex:
        raise ApplyError("not_found", "execution_not_found", {"execution_id": exec_id})
    ex[exec_id]["receipt"] = {"at_nonce": int(env.nonce), "payload": payload}
    gov["executions_by_id"] = ex
    return {"applied": "GOV_EXECUTION_RECEIPT", "execution_id": exec_id}


# -----------------------------
# Protocol upgrades (MVP registry)
# -----------------------------

def _apply_protocol_upgrade_declare(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    up_id = _mk_id("upgrade", env, payload.get("upgrade_id"))
    upgrades = _ensure_root_dict(state, "protocol_upgrades")
    if up_id in upgrades:
        raise ApplyError("duplicate", "upgrade_id_exists", {"upgrade_id": up_id})
    upgrades[up_id] = {"id": up_id, "declared_by": env.signer, "at_nonce": int(env.nonce), "payload": payload, "active": False}
    return {"applied": "PROTOCOL_UPGRADE_DECLARE", "upgrade_id": up_id}


def _apply_protocol_upgrade_activate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    up_id = _as_str(payload.get("upgrade_id")).strip()
    if not up_id:
        raise ApplyError("invalid_payload", "missing_upgrade_id", {"tx_type": env.tx_type})
    upgrades = _ensure_root_dict(state, "protocol_upgrades")
    u = upgrades.get(up_id)
    if not isinstance(u, dict):
        raise ApplyError("not_found", "upgrade_not_found", {"upgrade_id": up_id})
    u["active"] = True
    u["activated_at_nonce"] = int(env.nonce)
    upgrades[up_id] = u
    return {"applied": "PROTOCOL_UPGRADE_ACTIVATE", "upgrade_id": up_id}


# -----------------------------
# Treasury (MVP wallets + spends + programs)
# -----------------------------

def _ensure_treasury(state: Json) -> Json:
    return _ensure_root_dict(state, "treasury")


def _ensure_wallets(state: Json) -> Json:
    tr = _ensure_treasury(state)
    w = tr.get("wallets_by_id")
    if not isinstance(w, dict):
        w = {}
        tr["wallets_by_id"] = w
    return w


def _ensure_spends(state: Json) -> Json:
    tr = _ensure_treasury(state)
    s = tr.get("spends_by_id")
    if not isinstance(s, dict):
        s = {}
        tr["spends_by_id"] = s
    return s


def _ensure_programs(state: Json) -> Json:
    tr = _ensure_treasury(state)
    p = tr.get("programs_by_id")
    if not isinstance(p, dict):
        p = {}
        tr["programs_by_id"] = p
    return p


def _apply_treasury_wallet_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    wallet_id = _mk_id("twallet", env, payload.get("wallet_id") or payload.get("treasury_id"))
    wallets = _ensure_wallets(state)
    if wallet_id in wallets:
        raise ApplyError("duplicate", "wallet_id_exists", {"wallet_id": wallet_id})
    wallets[wallet_id] = {
        "id": wallet_id,
        "created_by": env.signer,
        "created_at_nonce": int(env.nonce),
        "signers": sorted(set(_as_list(payload.get("signers")))) if _as_list(payload.get("signers")) else [env.signer],
        "policy": payload.get("policy") if isinstance(payload.get("policy"), dict) else {},
        "balance": 0,
    }
    return {"applied": "TREASURY_WALLET_CREATE", "wallet_id": wallet_id}


def _apply_treasury_signer_add(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    signer = _as_str(payload.get("signer")).strip()
    if not wallet_id or not signer:
        raise ApplyError("invalid_payload", "missing_wallet_or_signer", {"tx_type": env.tx_type})
    wallets = _ensure_wallets(state)
    w = wallets.get(wallet_id)
    if not isinstance(w, dict):
        raise ApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})
    signers = w.get("signers")
    if not isinstance(signers, list):
        signers = []
    if signer not in signers:
        signers.append(signer)
        signers.sort()
    w["signers"] = signers
    w["signers_updated_at_nonce"] = int(env.nonce)
    wallets[wallet_id] = w
    return {"applied": "TREASURY_SIGNER_ADD", "wallet_id": wallet_id, "signer": signer}


def _apply_treasury_signer_remove(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    signer = _as_str(payload.get("signer")).strip()
    if not wallet_id or not signer:
        raise ApplyError("invalid_payload", "missing_wallet_or_signer", {"tx_type": env.tx_type})
    wallets = _ensure_wallets(state)
    w = wallets.get(wallet_id)
    if not isinstance(w, dict):
        raise ApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})
    signers = w.get("signers")
    if not isinstance(signers, list):
        signers = []
    signers = [s for s in signers if s != signer]
    w["signers"] = sorted(signers)
    w["signers_updated_at_nonce"] = int(env.nonce)
    wallets[wallet_id] = w
    return {"applied": "TREASURY_SIGNER_REMOVE", "wallet_id": wallet_id, "signer": signer}


def _apply_treasury_policy_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    policy = payload.get("policy")
    if not wallet_id or not isinstance(policy, dict):
        raise ApplyError("invalid_payload", "missing_wallet_or_policy", {"tx_type": env.tx_type})
    wallets = _ensure_wallets(state)
    w = wallets.get(wallet_id)
    if not isinstance(w, dict):
        raise ApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})
    w["policy"] = policy
    w["policy_set_at_nonce"] = int(env.nonce)
    wallets[wallet_id] = w
    return {"applied": "TREASURY_POLICY_SET", "wallet_id": wallet_id}


def _apply_treasury_spend_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    to = _as_str(payload.get("to")).strip()
    amount = payload.get("amount")
    if not wallet_id or not to or amount is None:
        raise ApplyError("invalid_payload", "missing_wallet_to_amount", {"tx_type": env.tx_type})
    spend_id = _mk_id("spend", env, payload.get("spend_id"))
    spends = _ensure_spends(state)
    if spend_id in spends:
        raise ApplyError("duplicate", "spend_id_exists", {"spend_id": spend_id})
    spends[spend_id] = {
        "id": spend_id,
        "wallet_id": wallet_id,
        "to": to,
        "amount": amount,
        "memo": _as_str(payload.get("memo")).strip(),
        "proposed_by": env.signer,
        "proposed_at_nonce": int(env.nonce),
        "status": "proposed",
        "signatures": {},
    }
    return {"applied": "TREASURY_SPEND_PROPOSE", "spend_id": spend_id}


def _apply_treasury_spend_sign(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
    sigs = s.get("signatures")
    if not isinstance(sigs, dict):
        sigs = {}
    sigs[env.signer] = {"at_nonce": int(env.nonce)}
    s["signatures"] = sigs
    s["last_signed_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "TREASURY_SPEND_SIGN", "spend_id": spend_id}


def _apply_treasury_spend_cancel(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
    s["status"] = "canceled"
    s["canceled_by"] = env.signer
    s["canceled_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "TREASURY_SPEND_CANCEL", "spend_id": spend_id}


def _apply_treasury_spend_expire(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
    s["status"] = "expired"
    s["expired_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "TREASURY_SPEND_EXPIRE", "spend_id": spend_id}


def _apply_treasury_spend_execute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
    s["status"] = "executed"
    s["executed_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "TREASURY_SPEND_EXECUTE", "spend_id": spend_id}


def _apply_treasury_program_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _mk_id("tprog", env, payload.get("program_id"))
    programs = _ensure_programs(state)
    if pid in programs:
        raise ApplyError("duplicate", "program_id_exists", {"program_id": pid})
    programs[pid] = {"id": pid, "created_by": env.signer, "at_nonce": int(env.nonce), "payload": payload, "closed": False}
    return {"applied": "TREASURY_PROGRAM_CREATE", "program_id": pid}


def _apply_treasury_program_update(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("program_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_program_id", {"tx_type": env.tx_type})
    programs = _ensure_programs(state)
    p = programs.get(pid)
    if not isinstance(p, dict):
        raise ApplyError("not_found", "program_not_found", {"program_id": pid})
    p["payload"] = payload
    p["updated_at_nonce"] = int(env.nonce)
    programs[pid] = p
    return {"applied": "TREASURY_PROGRAM_UPDATE", "program_id": pid}


def _apply_treasury_program_close(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("program_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_program_id", {"tx_type": env.tx_type})
    programs = _ensure_programs(state)
    p = programs.get(pid)
    if not isinstance(p, dict):
        raise ApplyError("not_found", "program_not_found", {"program_id": pid})
    p["closed"] = True
    p["closed_at_nonce"] = int(env.nonce)
    programs[pid] = p
    return {"applied": "TREASURY_PROGRAM_CLOSE", "program_id": pid}


def _apply_treasury_audit_anchor_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    tr = _ensure_treasury(state)
    tr["audit_anchor"] = {"at_nonce": int(env.nonce), "payload": payload}
    return {"applied": "TREASURY_AUDIT_ANCHOR_SET"}


# -----------------------------
# Stake / Slash (MVP bookkeeping)
# -----------------------------

def _ensure_stakes(state: Json) -> Json:
    return _ensure_root_dict(state, "stakes_by_account")


def _apply_stake_bond(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    amount = payload.get("amount")
    if amount is None:
        raise ApplyError("invalid_payload", "missing_amount", {"tx_type": env.tx_type})
    stakes = _ensure_stakes(state)
    s = stakes.get(env.signer)
    if not isinstance(s, dict):
        s = {"bonded": 0, "pending_unbond": 0}
    s["bonded"] = (s.get("bonded") or 0) + amount
    s["bonded_at_nonce"] = int(env.nonce)
    stakes[env.signer] = s
    return {"applied": "STAKE_BOND", "account_id": env.signer}


def _apply_stake_unbond_request(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    amount = payload.get("amount")
    if amount is None:
        raise ApplyError("invalid_payload", "missing_amount", {"tx_type": env.tx_type})
    stakes = _ensure_stakes(state)
    s = stakes.get(env.signer)
    if not isinstance(s, dict):
        s = {"bonded": 0, "pending_unbond": 0}
    s["pending_unbond"] = (s.get("pending_unbond") or 0) + amount
    s["unbond_requested_at_nonce"] = int(env.nonce)
    stakes[env.signer] = s
    return {"applied": "STAKE_UNBOND_REQUEST", "account_id": env.signer}


def _apply_slash_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    sid = _mk_id("slash", env, payload.get("slash_id"))
    slashes = _ensure_root_dict(state, "slashes_by_id")
    if sid in slashes:
        raise ApplyError("duplicate", "slash_id_exists", {"slash_id": sid})
    slashes[sid] = {"id": sid, "payload": payload, "proposed_by": env.signer, "at_nonce": int(env.nonce), "votes": {}}
    return {"applied": "SLASH_PROPOSE", "slash_id": sid}


def _apply_slash_vote(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    sid = _as_str(payload.get("slash_id")).strip()
    if not sid:
        raise ApplyError("invalid_payload", "missing_slash_id", {"tx_type": env.tx_type})
    slashes = _ensure_root_dict(state, "slashes_by_id")
    s = slashes.get(sid)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "slash_not_found", {"slash_id": sid})
    votes = s.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    votes[env.signer] = {"vote": payload.get("vote"), "at_nonce": int(env.nonce)}
    s["votes"] = votes
    slashes[sid] = s
    return {"applied": "SLASH_VOTE", "slash_id": sid}


# -----------------------------
# Reward opt-in
# -----------------------------

def _apply_reward_pool_opt_in_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    enabled = payload.get("enabled")
    enabled = True if enabled is None else bool(enabled)
    opt = _ensure_root_dict(state, "reward_pool_opt_in")
    opt[env.signer] = {"enabled": enabled, "at_nonce": int(env.nonce)}
    return {"applied": "REWARD_POOL_OPT_IN_SET", "enabled": enabled}


# END WEALL REMAINING CANON TXS (AUTO-GENERATED)
'''


def main() -> None:
    if not DOMAIN_APPLY.exists():
        raise SystemExit(f"domain_apply not found at {DOMAIN_APPLY}")

    src = DOMAIN_APPLY.read_text(encoding="utf-8")

    if INSERT_MARKER_BEGIN in src:
        # already patched; still do rewires
        patched = src
    else:
        # insert before _normalize_tags (stable anchor in your file)
        anchor = "def _normalize_tags("
        idx = src.find(anchor)
        if idx < 0:
            raise SystemExit("Could not find insertion anchor: def _normalize_tags(")

        patched = src[:idx] + INSERT_BLOCK + "\n\n" + src[idx:]

    # Rewire apply_tx branches currently pointing to _apply_canon_missing
    rewires = {
        # Identity
        "ACCOUNT_BAN": "_apply_account_ban",
        "ACCOUNT_REINSTATE": "_apply_account_reinstate",

        # Dispute
        "DISPUTE_OPEN": "_apply_dispute_open",
        "DISPUTE_STAGE_SET": "_apply_dispute_stage_set",
        "DISPUTE_EVIDENCE_DECLARE": "_apply_dispute_evidence_declare",
        "DISPUTE_EVIDENCE_BIND": "_apply_dispute_evidence_bind",
        "DISPUTE_JUROR_ASSIGN": "_apply_dispute_juror_assign",
        "DISPUTE_JUROR_ACCEPT": "_apply_dispute_juror_accept",
        "DISPUTE_JUROR_DECLINE": "_apply_dispute_juror_decline",
        "DISPUTE_JUROR_ATTENDANCE": "_apply_dispute_juror_attendance",
        "DISPUTE_VOTE_SUBMIT": "_apply_dispute_vote_submit",
        "DISPUTE_RESOLVE": "_apply_dispute_resolve",
        "DISPUTE_APPEAL": "_apply_dispute_appeal",
        "DISPUTE_FINAL_RECEIPT": "_apply_dispute_final_receipt",

        # Content moderation knobs
        "CONTENT_LABEL_SET": "_apply_content_label_set",
        "CONTENT_VISIBILITY_SET": "_apply_content_visibility_set",
        "CONTENT_THREAD_LOCK_SET": "_apply_content_thread_lock_set",
        "CONTENT_ESCALATE_TO_DISPUTE": "_apply_content_escalate_to_dispute",
        "CONTENT_SHARE_CREATE": "_apply_content_share_create",

        # Governance
        "GOV_PROPOSAL_CREATE": "_apply_gov_proposal_create",
        "GOV_PROPOSAL_EDIT": "_apply_gov_proposal_edit",
        "GOV_PROPOSAL_WITHDRAW": "_apply_gov_proposal_withdraw",
        "GOV_STAGE_SET": "_apply_gov_stage_set",
        "GOV_VOTE_CAST": "_apply_gov_vote_cast",
        "GOV_VOTE_REVOKE": "_apply_gov_vote_revoke",
        "GOV_DELEGATION_SET": "_apply_gov_delegation_set",
        "GOV_QUORUM_SET": "_apply_gov_quorum_set",
        "GOV_RULES_SET": "_apply_gov_rules_set",
        "GOV_EXECUTE": "_apply_gov_execute",
        "GOV_EXECUTION_RECEIPT": "_apply_gov_execution_receipt",

        # Protocol upgrades
        "PROTOCOL_UPGRADE_DECLARE": "_apply_protocol_upgrade_declare",
        "PROTOCOL_UPGRADE_ACTIVATE": "_apply_protocol_upgrade_activate",

        # Treasury
        "TREASURY_WALLET_CREATE": "_apply_treasury_wallet_create",
        "TREASURY_SIGNER_ADD": "_apply_treasury_signer_add",
        "TREASURY_SIGNER_REMOVE": "_apply_treasury_signer_remove",
        "TREASURY_POLICY_SET": "_apply_treasury_policy_set",
        "TREASURY_SPEND_PROPOSE": "_apply_treasury_spend_propose",
        "TREASURY_SPEND_SIGN": "_apply_treasury_spend_sign",
        "TREASURY_SPEND_CANCEL": "_apply_treasury_spend_cancel",
        "TREASURY_SPEND_EXPIRE": "_apply_treasury_spend_expire",
        "TREASURY_SPEND_EXECUTE": "_apply_treasury_spend_execute",
        "TREASURY_PROGRAM_CREATE": "_apply_treasury_program_create",
        "TREASURY_PROGRAM_UPDATE": "_apply_treasury_program_update",
        "TREASURY_PROGRAM_CLOSE": "_apply_treasury_program_close",
        "TREASURY_AUDIT_ANCHOR_SET": "_apply_treasury_audit_anchor_set",

        # Stake / Slash
        "STAKE_BOND": "_apply_stake_bond",
        "STAKE_UNBOND_REQUEST": "_apply_stake_unbond_request",
        "SLASH_PROPOSE": "_apply_slash_propose",
        "SLASH_VOTE": "_apply_slash_vote",

        # Reward opt-in
        "REWARD_POOL_OPT_IN_SET": "_apply_reward_pool_opt_in_set",

        # Profile/social
        "PROFILE_UPDATE": "_apply_profile_update",
        "FOLLOW_SET": "_apply_follow_set",
        "MUTE_SET": "_apply_mute_set",

        # Direct messages
        "DIRECT_MESSAGE_SEND": "_apply_direct_message_send",
        "DIRECT_MESSAGE_REDACT": "_apply_direct_message_redact",

        # Existing implementations that were incorrectly wired to canon_missing:
        "INDEX_ANCHOR_SET": "_apply_index_anchor_set",
        "INDEX_TOPIC_REGISTER": "_apply_index_topic_register",
        "INDEX_TOPIC_ANCHOR_SET": "_apply_index_topic_anchor_set",
        "NOTIFICATION_SUBSCRIBE": "_apply_notification_subscribe",
        "NOTIFICATION_UNSUBSCRIBE": "_apply_notification_unsubscribe",
        "NOTIFICATION_EMIT_RECEIPT": "_apply_notification_emit_receipt",
    }

    def rewire_branch(text: str, tx_type: str, fn: str) -> str:
        pat = re.compile(
            rf'(if t == "{re.escape(tx_type)}":\s*\n\s*)return _apply_canon_missing\(([^)]*)\)',
            re.M,
        )
        return pat.sub(rf'\1return {fn}(\2)', text)

    out = patched
    for tx, fn in rewires.items():
        out = rewire_branch(out, tx, fn)

    DOMAIN_APPLY.write_text(out, encoding="utf-8")
    print(f"Patched: {DOMAIN_APPLY}")


if __name__ == "__main__":
    main()
