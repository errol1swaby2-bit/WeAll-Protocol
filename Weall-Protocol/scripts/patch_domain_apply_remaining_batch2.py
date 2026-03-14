#!/usr/bin/env python3
"""
Finish the remaining canon txs in domain_apply.py (the 57 still routing to _apply_canon_missing).

- Inserts deterministic MVP apply functions (idempotent if markers already exist)
- Rewires apply_tx dispatch branches that return _apply_canon_missing(...) to call real handlers

Run:
  python3 scripts/patch_domain_apply_remaining_batch2.py
  pytest -q
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_APPLY = REPO_ROOT / "src" / "weall" / "runtime" / "domain_apply.py"

BEGIN = "# BEGIN WEALL REMAINING CANON TXS BATCH2 (AUTO-GENERATED)\n"
END = "# END WEALL REMAINING CANON TXS BATCH2 (AUTO-GENERATED)\n"

INSERT_BLOCK = r'''# BEGIN WEALL REMAINING CANON TXS BATCH2 (AUTO-GENERATED)
# Deterministic MVP semantics for txs that previously routed to _apply_canon_missing(...).
# Goals:
# - Always deterministic
# - Never delete history (prefer append-only receipts/logs)
# - Keep “real” econ / consensus semantics minimal but structurally correct

def _ensure_root_dict(state: Json, key: str) -> Json:
    return _ensure_dict_root(state, key)


def _ensure_root_list(state: Json, key: str) -> list:
    return _ensure_list_root(state, key)


def _mk_id(prefix: str, env: TxEnvelope, provided: object) -> str:
    s = _as_str(provided).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{env.nonce}"


# -----------------------------------------------------------------------------
# Epochs & rewards (MVP bookkeeping)
# -----------------------------------------------------------------------------

def _ensure_epochs(state: Json) -> Json:
    return _ensure_root_dict(state, "epochs_by_id")


def _apply_epoch_open(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    epoch_id = _mk_id("epoch", env, payload.get("epoch_id"))
    epochs = _ensure_epochs(state)
    if epoch_id in epochs:
        raise ApplyError("duplicate", "epoch_exists", {"epoch_id": epoch_id})
    epochs[epoch_id] = {
        "id": epoch_id,
        "open": True,
        "opened_at_nonce": int(env.nonce),
        "payload": payload,
    }
    state["active_epoch_id"] = epoch_id
    return {"applied": "EPOCH_OPEN", "epoch_id": epoch_id}


def _apply_epoch_close(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    epoch_id = _as_str(payload.get("epoch_id") or state.get("active_epoch_id")).strip()
    if not epoch_id:
        raise ApplyError("invalid_payload", "missing_epoch_id", {"tx_type": env.tx_type})
    epochs = _ensure_epochs(state)
    e = epochs.get(epoch_id)
    if not isinstance(e, dict):
        raise ApplyError("not_found", "epoch_not_found", {"epoch_id": epoch_id})
    e["open"] = False
    e["closed_at_nonce"] = int(env.nonce)
    e["close_payload"] = payload
    epochs[epoch_id] = e
    if state.get("active_epoch_id") == epoch_id:
        state["active_epoch_id"] = ""
    return {"applied": "EPOCH_CLOSE", "epoch_id": epoch_id}


def _ensure_rewards(state: Json) -> Json:
    return _ensure_root_dict(state, "rewards")


def _apply_creator_reward_allocate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    r = _ensure_rewards(state)
    arr = r.get("creator_allocations")
    if not isinstance(arr, list):
        arr = []
    arr.append({"at_nonce": int(env.nonce), "payload": payload})
    r["creator_allocations"] = arr
    return {"applied": "CREATOR_REWARD_ALLOCATE"}


def _apply_treasury_reward_allocate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    r = _ensure_rewards(state)
    arr = r.get("treasury_allocations")
    if not isinstance(arr, list):
        arr = []
    arr.append({"at_nonce": int(env.nonce), "payload": payload})
    r["treasury_allocations"] = arr
    return {"applied": "TREASURY_REWARD_ALLOCATE"}


def _apply_forfeiture_apply(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    r = _ensure_rewards(state)
    f = r.get("forfeitures")
    if not isinstance(f, list):
        f = []
    f.append({"at_nonce": int(env.nonce), "payload": payload})
    r["forfeitures"] = f
    return {"applied": "FORFEITURE_APPLY"}


# -----------------------------------------------------------------------------
# Reputation (MVP)
# -----------------------------------------------------------------------------

def _ensure_rep(state: Json) -> Json:
    return _ensure_root_dict(state, "reputation")


def _apply_reputation_delta_apply(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("account_id") or payload.get("target")).strip()
    delta = payload.get("delta")
    if not target or delta is None:
        raise ApplyError("invalid_payload", "missing_target_or_delta", {"tx_type": env.tx_type})

    rep = _ensure_rep(state)
    log = rep.get("deltas")
    if not isinstance(log, list):
        log = []
    log.append({"at_nonce": int(env.nonce), "target": target, "delta": delta, "payload": payload})
    rep["deltas"] = log

    # Apply to account if present (deterministic)
    acct = _create_default_account(state, target)
    try:
        cur = float(acct.get("reputation") or 0.0)
        acct["reputation"] = cur + float(delta)
    except Exception:
        # If delta is non-numeric, just record it; do not mutate numeric reputation.
        pass

    return {"applied": "REPUTATION_DELTA_APPLY", "account_id": target}


def _apply_reputation_threshold_cross(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    rep = _ensure_rep(state)
    events = rep.get("threshold_cross_events")
    if not isinstance(events, list):
        events = []
    events.append({"at_nonce": int(env.nonce), "payload": payload})
    rep["threshold_cross_events"] = events
    return {"applied": "REPUTATION_THRESHOLD_CROSS"}


# -----------------------------------------------------------------------------
# Roles / eligibility (MVP)
# -----------------------------------------------------------------------------

def _ensure_roles_admin(state: Json) -> Json:
    return _ensure_root_dict(state, "role_admin")


def _apply_role_eligibility_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    role = _as_str(payload.get("role")).strip()
    if not role:
        raise ApplyError("invalid_payload", "missing_role", {"tx_type": env.tx_type})
    ra = _ensure_roles_admin(state)
    rules = ra.get("eligibility")
    if not isinstance(rules, dict):
        rules = {}
    rules[role] = {"at_nonce": int(env.nonce), "payload": payload}
    ra["eligibility"] = rules
    return {"applied": "ROLE_ELIGIBILITY_SET", "role": role}


def _apply_role_eligibility_revoke(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    role = _as_str(payload.get("role")).strip()
    if not role:
        raise ApplyError("invalid_payload", "missing_role", {"tx_type": env.tx_type})
    ra = _ensure_roles_admin(state)
    rules = ra.get("eligibility")
    if not isinstance(rules, dict):
        rules = {}
    rules.pop(role, None)
    ra["eligibility"] = rules
    return {"applied": "ROLE_ELIGIBILITY_REVOKE", "role": role}


def _apply_role_gov_executor_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    executor = _as_str(payload.get("executor") or payload.get("account_id")).strip()
    if not executor:
        raise ApplyError("invalid_payload", "missing_executor", {"tx_type": env.tx_type})
    ra = _ensure_roles_admin(state)
    ra["gov_executor"] = {"executor": executor, "at_nonce": int(env.nonce)}
    return {"applied": "ROLE_GOV_EXECUTOR_SET", "executor": executor}


# Canon roles state already exists under state["roles"]; we store role membership in a deterministic place too.
def _ensure_role_members(state: Json, role: str) -> Json:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    members = roles.get(role)
    if not isinstance(members, dict):
        members = {}
        roles[role] = members
    return members


def _set_role_status(state: Json, *, role: str, account_id: str, status: str, at_nonce: int) -> None:
    members = _ensure_role_members(state, role)
    entry = members.get(account_id)
    if not isinstance(entry, dict):
        entry = {"account_id": account_id}
    entry["status"] = status
    entry["updated_at_nonce"] = at_nonce
    members[account_id] = entry


def _apply_role_juror_enroll(state: Json, env: TxEnvelope) -> Json:
    _set_role_status(state, role="jurors", account_id=env.signer, status="enrolled", at_nonce=int(env.nonce))
    return {"applied": "ROLE_JUROR_ENROLL", "account_id": env.signer}


def _apply_role_juror_activate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id") or env.signer).strip()
    _set_role_status(state, role="jurors", account_id=acct, status="active", at_nonce=int(env.nonce))
    return {"applied": "ROLE_JUROR_ACTIVATE", "account_id": acct}


def _apply_role_juror_suspend(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    _set_role_status(state, role="jurors", account_id=acct, status="suspended", at_nonce=int(env.nonce))
    return {"applied": "ROLE_JUROR_SUSPEND", "account_id": acct}


def _apply_role_juror_reinstate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    _set_role_status(state, role="jurors", account_id=acct, status="active", at_nonce=int(env.nonce))
    return {"applied": "ROLE_JUROR_REINSTATE", "account_id": acct}


def _apply_role_validator_activate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    _set_role_status(state, role="validators", account_id=acct, status="active", at_nonce=int(env.nonce))
    return {"applied": "ROLE_VALIDATOR_ACTIVATE", "account_id": acct}


def _apply_role_validator_suspend(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    _set_role_status(state, role="validators", account_id=acct, status="suspended", at_nonce=int(env.nonce))
    return {"applied": "ROLE_VALIDATOR_SUSPEND", "account_id": acct}


def _apply_role_node_operator_enroll(state: Json, env: TxEnvelope) -> Json:
    _set_role_status(state, role="node_operators", account_id=env.signer, status="enrolled", at_nonce=int(env.nonce))
    return {"applied": "ROLE_NODE_OPERATOR_ENROLL", "account_id": env.signer}


def _apply_role_node_operator_activate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id") or env.signer).strip()
    _set_role_status(state, role="node_operators", account_id=acct, status="active", at_nonce=int(env.nonce))
    return {"applied": "ROLE_NODE_OPERATOR_ACTIVATE", "account_id": acct}


def _apply_role_node_operator_suspend(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    _set_role_status(state, role="node_operators", account_id=acct, status="suspended", at_nonce=int(env.nonce))
    return {"applied": "ROLE_NODE_OPERATOR_SUSPEND", "account_id": acct}


# Emissaries (MVP: nominations + votes + seated list)
def _ensure_emissary_state(state: Json) -> Json:
    ra = _ensure_roles_admin(state)
    es = ra.get("emissaries")
    if not isinstance(es, dict):
        es = {"nominations": {}, "votes": {}, "seated": []}
        ra["emissaries"] = es
    return es


def _apply_role_emissary_nominate(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    nominee = _as_str(payload.get("nominee") or payload.get("account_id")).strip()
    if not nominee:
        raise ApplyError("invalid_payload", "missing_nominee", {"tx_type": env.tx_type})
    es = _ensure_emissary_state(state)
    noms = es.get("nominations")
    if not isinstance(noms, dict):
        noms = {}
    noms[nominee] = {"nominated_by": env.signer, "at_nonce": int(env.nonce), "payload": payload}
    es["nominations"] = noms
    return {"applied": "ROLE_EMISSARY_NOMINATE", "nominee": nominee}


def _apply_role_emissary_vote(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    nominee = _as_str(payload.get("nominee") or payload.get("account_id")).strip()
    vote = payload.get("vote")
    if not nominee:
        raise ApplyError("invalid_payload", "missing_nominee", {"tx_type": env.tx_type})
    es = _ensure_emissary_state(state)
    votes = es.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    by_voter = votes.get(env.signer)
    if not isinstance(by_voter, dict):
        by_voter = {}
    by_voter[nominee] = {"vote": vote, "at_nonce": int(env.nonce)}
    votes[env.signer] = by_voter
    es["votes"] = votes
    return {"applied": "ROLE_EMISSARY_VOTE", "nominee": nominee}


def _apply_role_emissary_seat(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    nominee = _as_str(payload.get("nominee") or payload.get("account_id")).strip()
    if not nominee:
        raise ApplyError("invalid_payload", "missing_nominee", {"tx_type": env.tx_type})
    es = _ensure_emissary_state(state)
    seated = es.get("seated")
    if not isinstance(seated, list):
        seated = []
    if nominee not in seated:
        seated.append(nominee)
        seated.sort()
    es["seated"] = seated
    return {"applied": "ROLE_EMISSARY_SEAT", "account_id": nominee}


def _apply_role_emissary_remove(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    es = _ensure_emissary_state(state)
    seated = es.get("seated")
    if not isinstance(seated, list):
        seated = []
    seated = [x for x in seated if x != acct]
    es["seated"] = seated
    return {"applied": "ROLE_EMISSARY_REMOVE", "account_id": acct}


# -----------------------------------------------------------------------------
# Snapshots (MVP)
# -----------------------------------------------------------------------------

def _ensure_snapshots(state: Json) -> Json:
    return _ensure_root_dict(state, "state_snapshots")


def _apply_state_snapshot_declare(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    sid = _mk_id("snapshot", env, payload.get("snapshot_id"))
    snaps = _ensure_snapshots(state)
    if sid in snaps:
        raise ApplyError("duplicate", "snapshot_exists", {"snapshot_id": sid})
    snaps[sid] = {"id": sid, "declared_at_nonce": int(env.nonce), "payload": payload, "accepted": False}
    return {"applied": "STATE_SNAPSHOT_DECLARE", "snapshot_id": sid}


def _apply_state_snapshot_accept(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    sid = _as_str(payload.get("snapshot_id")).strip()
    if not sid:
        raise ApplyError("invalid_payload", "missing_snapshot_id", {"tx_type": env.tx_type})
    snaps = _ensure_snapshots(state)
    s = snaps.get(sid)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "snapshot_not_found", {"snapshot_id": sid})
    s["accepted"] = True
    s["accepted_at_nonce"] = int(env.nonce)
    s["accept_payload"] = payload
    snaps[sid] = s
    return {"applied": "STATE_SNAPSHOT_ACCEPT", "snapshot_id": sid}


# -----------------------------------------------------------------------------
# Stake / slashing finalize (MVP)
# -----------------------------------------------------------------------------

def _apply_stake_unbond_finalize(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    account_id = _as_str(payload.get("account_id") or env.signer).strip()
    amount = payload.get("amount")
    if amount is None:
        raise ApplyError("invalid_payload", "missing_amount", {"tx_type": env.tx_type})
    stakes = _ensure_root_dict(state, "stakes_by_account")
    s = stakes.get(account_id)
    if not isinstance(s, dict):
        s = {"bonded": 0, "pending_unbond": 0}
    try:
        s["pending_unbond"] = max(0, float(s.get("pending_unbond") or 0) - float(amount))
    except Exception:
        pass
    s["unbond_finalized_at_nonce"] = int(env.nonce)
    stakes[account_id] = s
    return {"applied": "STAKE_UNBOND_FINALIZE", "account_id": account_id}


def _apply_slash_execute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    slash_id = _as_str(payload.get("slash_id")).strip()
    slashes = _ensure_root_dict(state, "slashes_by_id")
    entry = slashes.get(slash_id) if slash_id else None
    # If we have a proposal recorded, mark it executed; otherwise just append a log.
    if isinstance(entry, dict):
        entry["executed"] = True
        entry["executed_at_nonce"] = int(env.nonce)
        entry["execute_payload"] = payload
        slashes[slash_id] = entry
    log = _ensure_root_list(state, "slash_exec_log")
    log.append({"at_nonce": int(env.nonce), "payload": payload})
    state["slash_exec_log"] = log
    return {"applied": "SLASH_EXECUTE", "slash_id": slash_id}


# -----------------------------------------------------------------------------
# Moderation receipts (append-only)
# -----------------------------------------------------------------------------

def _apply_mod_action_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    log = _ensure_root_list(state, "mod_action_receipts")
    log.append({"at_nonce": int(env.nonce), "payload": payload})
    state["mod_action_receipts"] = log
    return {"applied": "MOD_ACTION_RECEIPT"}


def _apply_flag_escalation_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    log = _ensure_root_list(state, "flag_escalation_receipts")
    log.append({"at_nonce": int(env.nonce), "payload": payload})
    state["flag_escalation_receipts"] = log
    return {"applied": "FLAG_ESCALATION_RECEIPT"}


def _apply_mempool_reject_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    log = _ensure_root_list(state, "mempool_reject_receipts")
    log.append({"at_nonce": int(env.nonce), "payload": payload})
    state["mempool_reject_receipts"] = log
    return {"applied": "MEMPOOL_REJECT_RECEIPT"}


# -----------------------------------------------------------------------------
# Governance “closing/tally/finalize/receipt” (MVP logs)
# -----------------------------------------------------------------------------

def _ensure_gov_state(state: Json) -> Json:
    gov = state.get("gov")
    if not isinstance(gov, dict):
        gov = {}
        state["gov"] = gov
    return gov


def _ensure_proposals_by_id(state: Json) -> Json:
    gov = _ensure_gov_state(state)
    p = gov.get("proposals_by_id")
    if not isinstance(p, dict):
        p = {}
        gov["proposals_by_id"] = p
    return p


def _apply_gov_voting_close(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_proposal_id", {"tx_type": env.tx_type})
    props = _ensure_proposals_by_id(state)
    pr = props.get(pid)
    if not isinstance(pr, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    pr["voting_closed_at_nonce"] = int(env.nonce)
    pr["stage"] = "voting_closed"
    pr["voting_close_payload"] = payload
    props[pid] = pr
    return {"applied": "GOV_VOTING_CLOSE", "proposal_id": pid}


def _apply_gov_tally_publish(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_proposal_id", {"tx_type": env.tx_type})
    props = _ensure_proposals_by_id(state)
    pr = props.get(pid)
    if not isinstance(pr, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    tallies = pr.get("tallies")
    if not isinstance(tallies, list):
        tallies = []
    tallies.append({"at_nonce": int(env.nonce), "payload": payload})
    pr["tallies"] = tallies
    pr["stage"] = "tallied"
    props[pid] = pr
    return {"applied": "GOV_TALLY_PUBLISH", "proposal_id": pid}


def _apply_gov_proposal_finalize(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    pid = _as_str(payload.get("proposal_id")).strip()
    if not pid:
        raise ApplyError("invalid_payload", "missing_proposal_id", {"tx_type": env.tx_type})
    props = _ensure_proposals_by_id(state)
    pr = props.get(pid)
    if not isinstance(pr, dict):
        raise ApplyError("not_found", "proposal_not_found", {"proposal_id": pid})
    pr["finalized_at_nonce"] = int(env.nonce)
    pr["stage"] = "finalized"
    pr["finalize_payload"] = payload
    props[pid] = pr
    return {"applied": "GOV_PROPOSAL_FINALIZE", "proposal_id": pid}


def _apply_gov_proposal_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    log = _ensure_root_list(state, "gov_proposal_receipts")
    log.append({"at_nonce": int(env.nonce), "payload": payload})
    state["gov_proposal_receipts"] = log
    return {"applied": "GOV_PROPOSAL_RECEIPT"}


# -----------------------------------------------------------------------------
# Groups: update + membership + roles + group treasury (MVP)
# -----------------------------------------------------------------------------

def _ensure_groups_by_id(state: Json) -> Json:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    g = roles.get("groups_by_id")
    if not isinstance(g, dict):
        g = {}
        roles["groups_by_id"] = g
    return g


def _get_group(state: Json, group_id: str) -> Json:
    groups = _ensure_groups_by_id(state)
    g = groups.get(group_id)
    if not isinstance(g, dict):
        raise ApplyError("not_found", "group_not_found", {"group_id": group_id})
    return g


def _apply_group_update(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    if not gid:
        raise ApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})
    g = _get_group(state, gid)
    # allow a few common keys; store rest under meta
    for k in ("name", "description", "visibility", "rules_cid"):
        if k in payload:
            g[k] = payload.get(k)
    meta = g.get("meta")
    if not isinstance(meta, dict):
        meta = {}
    extra = payload.get("meta")
    if isinstance(extra, dict):
        for k, v in extra.items():
            meta[str(k)] = v
    g["meta"] = meta
    g["updated_at_nonce"] = int(env.nonce)
    _ensure_groups_by_id(state)[gid] = g
    return {"applied": "GROUP_UPDATE", "group_id": gid}


def _apply_group_role_grant(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    acct = _as_str(payload.get("account_id")).strip()
    role = _as_str(payload.get("role")).strip()
    if not gid or not acct or not role:
        raise ApplyError("invalid_payload", "missing_group_account_role", {"tx_type": env.tx_type})
    g = _get_group(state, gid)
    roles = g.get("member_roles")
    if not isinstance(roles, dict):
        roles = {}
    rs = roles.get(acct)
    if not isinstance(rs, list):
        rs = []
    if role not in rs:
        rs.append(role)
        rs.sort()
    roles[acct] = rs
    g["member_roles"] = roles
    g["role_grant_at_nonce"] = int(env.nonce)
    _ensure_groups_by_id(state)[gid] = g
    return {"applied": "GROUP_ROLE_GRANT", "group_id": gid, "account_id": acct, "role": role}


def _apply_group_role_revoke(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    acct = _as_str(payload.get("account_id")).strip()
    role = _as_str(payload.get("role")).strip()
    if not gid or not acct or not role:
        raise ApplyError("invalid_payload", "missing_group_account_role", {"tx_type": env.tx_type})
    g = _get_group(state, gid)
    roles = g.get("member_roles")
    if not isinstance(roles, dict):
        roles = {}
    rs = roles.get(acct)
    if not isinstance(rs, list):
        rs = []
    rs = [r for r in rs if r != role]
    roles[acct] = sorted(rs)
    g["member_roles"] = roles
    g["role_revoke_at_nonce"] = int(env.nonce)
    _ensure_groups_by_id(state)[gid] = g
    return {"applied": "GROUP_ROLE_REVOKE", "group_id": gid, "account_id": acct, "role": role}


def _apply_group_membership_request(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    if not gid:
        raise ApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})
    g = _get_group(state, gid)
    reqs = g.get("membership_requests")
    if not isinstance(reqs, dict):
        reqs = {}
    reqs[env.signer] = {"status": "requested", "at_nonce": int(env.nonce), "payload": payload}
    g["membership_requests"] = reqs
    _ensure_groups_by_id(state)[gid] = g
    return {"applied": "GROUP_MEMBERSHIP_REQUEST", "group_id": gid, "account_id": env.signer}


def _apply_group_membership_decide(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    acct = _as_str(payload.get("account_id")).strip()
    decision = _as_str(payload.get("decision") or payload.get("status")).strip().lower()
    if not gid or not acct or decision not in {"approved", "denied"}:
        raise ApplyError("invalid_payload", "missing_or_bad_decision", {"tx_type": env.tx_type})
    g = _get_group(state, gid)
    reqs = g.get("membership_requests")
    if not isinstance(reqs, dict):
        reqs = {}
    r = reqs.get(acct)
    if not isinstance(r, dict):
        r = {"at_nonce": int(env.nonce)}
    r["status"] = decision
    r["decided_by"] = env.signer
    r["decided_at_nonce"] = int(env.nonce)
    reqs[acct] = r
    g["membership_requests"] = reqs

    members = g.get("members")
    if not isinstance(members, list):
        members = []
    if decision == "approved" and acct not in members:
        members.append(acct)
        members.sort()
    g["members"] = members

    _ensure_groups_by_id(state)[gid] = g
    return {"applied": "GROUP_MEMBERSHIP_DECIDE", "group_id": gid, "account_id": acct, "decision": decision}


def _apply_group_membership_remove(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    acct = _as_str(payload.get("account_id")).strip()
    if not gid or not acct:
        raise ApplyError("invalid_payload", "missing_group_or_account", {"tx_type": env.tx_type})
    g = _get_group(state, gid)
    members = g.get("members")
    if not isinstance(members, list):
        members = []
    members = [m for m in members if m != acct]
    g["members"] = sorted(members)
    g["member_removed_at_nonce"] = int(env.nonce)
    _ensure_groups_by_id(state)[gid] = g
    return {"applied": "GROUP_MEMBERSHIP_REMOVE", "group_id": gid, "account_id": acct}


# Group treasury namespace (parallel to treasury batch1, but scoped under group_id)
def _ensure_group_treasury(state: Json) -> Json:
    return _ensure_root_dict(state, "group_treasury")


def _ensure_group_wallets(state: Json) -> Json:
    gt = _ensure_group_treasury(state)
    w = gt.get("wallets_by_id")
    if not isinstance(w, dict):
        w = {}
        gt["wallets_by_id"] = w
    return w


def _apply_group_treasury_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    gid = _as_str(payload.get("group_id")).strip()
    if not gid:
        raise ApplyError("invalid_payload", "missing_group_id", {"tx_type": env.tx_type})
    wallet_id = _mk_id("gtwallet", env, payload.get("wallet_id") or payload.get("treasury_id"))
    wallets = _ensure_group_wallets(state)
    if wallet_id in wallets:
        raise ApplyError("duplicate", "wallet_exists", {"wallet_id": wallet_id})
    wallets[wallet_id] = {"id": wallet_id, "group_id": gid, "created_by": env.signer, "at_nonce": int(env.nonce), "payload": payload}
    return {"applied": "GROUP_TREASURY_CREATE", "wallet_id": wallet_id}


def _apply_group_treasury_policy_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    if not wallet_id:
        raise ApplyError("invalid_payload", "missing_wallet_id", {"tx_type": env.tx_type})
    wallets = _ensure_group_wallets(state)
    w = wallets.get(wallet_id)
    if not isinstance(w, dict):
        raise ApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})
    w["policy"] = payload.get("policy") if isinstance(payload.get("policy"), dict) else payload
    w["policy_set_at_nonce"] = int(env.nonce)
    wallets[wallet_id] = w
    return {"applied": "GROUP_TREASURY_POLICY_SET", "wallet_id": wallet_id}


def _ensure_group_spends(state: Json) -> Json:
    gt = _ensure_group_treasury(state)
    s = gt.get("spends_by_id")
    if not isinstance(s, dict):
        s = {}
        gt["spends_by_id"] = s
    return s


def _apply_group_treasury_spend_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    to = _as_str(payload.get("to")).strip()
    amount = payload.get("amount")
    if not wallet_id or not to or amount is None:
        raise ApplyError("invalid_payload", "missing_wallet_to_amount", {"tx_type": env.tx_type})
    spend_id = _mk_id("gtspend", env, payload.get("spend_id"))
    spends = _ensure_group_spends(state)
    if spend_id in spends:
        raise ApplyError("duplicate", "spend_exists", {"spend_id": spend_id})
    spends[spend_id] = {"id": spend_id, "wallet_id": wallet_id, "to": to, "amount": amount, "status": "proposed", "signatures": {}, "at_nonce": int(env.nonce), "payload": payload}
    return {"applied": "GROUP_TREASURY_SPEND_PROPOSE", "spend_id": spend_id}


def _apply_group_treasury_spend_sign(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
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
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
    s["status"] = "canceled"
    s["canceled_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_CANCEL", "spend_id": spend_id}


def _apply_group_treasury_spend_expire(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
    s["status"] = "expired"
    s["expired_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_EXPIRE", "spend_id": spend_id}


def _apply_group_treasury_spend_execute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise ApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})
    spends = _ensure_group_spends(state)
    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise ApplyError("not_found", "spend_not_found", {"spend_id": spend_id})
    s["status"] = "executed"
    s["executed_at_nonce"] = int(env.nonce)
    spends[spend_id] = s
    return {"applied": "GROUP_TREASURY_SPEND_EXECUTE", "spend_id": spend_id}


def _apply_group_treasury_audit_anchor_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    gt = _ensure_group_treasury(state)
    gt["audit_anchor"] = {"at_nonce": int(env.nonce), "payload": payload}
    return {"applied": "GROUP_TREASURY_AUDIT_ANCHOR_SET"}


# -----------------------------------------------------------------------------
# Performance system (MVP)
# -----------------------------------------------------------------------------

def _ensure_perf(state: Json) -> Json:
    return _ensure_root_dict(state, "performance")


def _apply_node_operator_performance_report(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    perf = _ensure_perf(state)
    r = perf.get("node_operator_reports")
    if not isinstance(r, list):
        r = []
    r.append({"by": env.signer, "at_nonce": int(env.nonce), "payload": payload})
    perf["node_operator_reports"] = r
    return {"applied": "NODE_OPERATOR_PERFORMANCE_REPORT"}


def _apply_creator_performance_report(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    perf = _ensure_perf(state)
    r = perf.get("creator_reports")
    if not isinstance(r, list):
        r = []
    r.append({"by": env.signer, "at_nonce": int(env.nonce), "payload": payload})
    perf["creator_reports"] = r
    return {"applied": "CREATOR_PERFORMANCE_REPORT"}


def _apply_performance_evaluate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    perf = _ensure_perf(state)
    ev = perf.get("evaluations")
    if not isinstance(ev, list):
        ev = []
    ev.append({"at_nonce": int(env.nonce), "payload": payload})
    perf["evaluations"] = ev
    return {"applied": "PERFORMANCE_EVALUATE"}


def _apply_performance_score_apply(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    perf = _ensure_perf(state)
    scores = perf.get("scores_by_account")
    if not isinstance(scores, dict):
        scores = {}
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    scores[acct] = {"at_nonce": int(env.nonce), "payload": payload}
    perf["scores_by_account"] = scores
    return {"applied": "PERFORMANCE_SCORE_APPLY", "account_id": acct}


# -----------------------------------------------------------------------------
# Rate limits (MVP)
# -----------------------------------------------------------------------------

def _ensure_rate_limits(state: Json) -> Json:
    return _ensure_root_dict(state, "rate_limits")


def _apply_rate_limit_policy_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    rl = _ensure_rate_limits(state)
    rl["policy"] = {"at_nonce": int(env.nonce), "payload": payload}
    return {"applied": "RATE_LIMIT_POLICY_SET"}


def _apply_rate_limit_strike_apply(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _as_str(payload.get("account_id")).strip()
    if not acct:
        raise ApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    rl = _ensure_rate_limits(state)
    strikes = rl.get("strikes_by_account")
    if not isinstance(strikes, dict):
        strikes = {}
    arr = strikes.get(acct)
    if not isinstance(arr, list):
        arr = []
    arr.append({"at_nonce": int(env.nonce), "payload": payload})
    strikes[acct] = arr
    rl["strikes_by_account"] = strikes
    return {"applied": "RATE_LIMIT_STRIKE_APPLY", "account_id": acct}


# -----------------------------------------------------------------------------
# Case system (MVP registry)
# -----------------------------------------------------------------------------

def _ensure_cases(state: Json) -> Json:
    return _ensure_root_dict(state, "cases")


def _apply_case_type_register(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    case_type = _as_str(payload.get("case_type")).strip()
    if not case_type:
        raise ApplyError("invalid_payload", "missing_case_type", {"tx_type": env.tx_type})
    cases = _ensure_cases(state)
    types = cases.get("types")
    if not isinstance(types, dict):
        types = {}
    types[case_type] = {"at_nonce": int(env.nonce), "payload": payload}
    cases["types"] = types
    return {"applied": "CASE_TYPE_REGISTER", "case_type": case_type}


def _apply_case_bind_to_dispute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    case_id = _mk_id("case", env, payload.get("case_id"))
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise ApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    cases = _ensure_cases(state)
    binds = cases.get("binds")
    if not isinstance(binds, dict):
        binds = {}
    binds[case_id] = {"dispute_id": dispute_id, "at_nonce": int(env.nonce), "payload": payload}
    cases["binds"] = binds
    return {"applied": "CASE_BIND_TO_DISPUTE", "case_id": case_id, "dispute_id": dispute_id}


def _apply_case_outcome_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    log = _ensure_root_list(state, "case_outcome_receipts")
    log.append({"at_nonce": int(env.nonce), "payload": payload})
    state["case_outcome_receipts"] = log
    return {"applied": "CASE_OUTCOME_RECEIPT"}


# END WEALL REMAINING CANON TXS BATCH2 (AUTO-GENERATED)
'''

REWIRES = {
    "EPOCH_OPEN": "_apply_epoch_open",
    "EPOCH_CLOSE": "_apply_epoch_close",
    "SLASH_EXECUTE": "_apply_slash_execute",
    "CREATOR_REWARD_ALLOCATE": "_apply_creator_reward_allocate",
    "TREASURY_REWARD_ALLOCATE": "_apply_treasury_reward_allocate",
    "FORFEITURE_APPLY": "_apply_forfeiture_apply",
    "REPUTATION_DELTA_APPLY": "_apply_reputation_delta_apply",
    "REPUTATION_THRESHOLD_CROSS": "_apply_reputation_threshold_cross",
    "ROLE_ELIGIBILITY_SET": "_apply_role_eligibility_set",
    "ROLE_ELIGIBILITY_REVOKE": "_apply_role_eligibility_revoke",
    "STATE_SNAPSHOT_DECLARE": "_apply_state_snapshot_declare",
    "STATE_SNAPSHOT_ACCEPT": "_apply_state_snapshot_accept",
    "ROLE_JUROR_ENROLL": "_apply_role_juror_enroll",
    "ROLE_JUROR_ACTIVATE": "_apply_role_juror_activate",
    "ROLE_JUROR_SUSPEND": "_apply_role_juror_suspend",
    "ROLE_JUROR_REINSTATE": "_apply_role_juror_reinstate",
    "ROLE_VALIDATOR_ACTIVATE": "_apply_role_validator_activate",
    "ROLE_VALIDATOR_SUSPEND": "_apply_role_validator_suspend",
    "ROLE_NODE_OPERATOR_ENROLL": "_apply_role_node_operator_enroll",
    "ROLE_NODE_OPERATOR_ACTIVATE": "_apply_role_node_operator_activate",
    "ROLE_NODE_OPERATOR_SUSPEND": "_apply_role_node_operator_suspend",
    "ROLE_EMISSARY_NOMINATE": "_apply_role_emissary_nominate",
    "ROLE_EMISSARY_VOTE": "_apply_role_emissary_vote",
    "ROLE_EMISSARY_SEAT": "_apply_role_emissary_seat",
    "ROLE_EMISSARY_REMOVE": "_apply_role_emissary_remove",
    "ROLE_GOV_EXECUTOR_SET": "_apply_role_gov_executor_set",
    "STAKE_UNBOND_FINALIZE": "_apply_stake_unbond_finalize",
    "MOD_ACTION_RECEIPT": "_apply_mod_action_receipt",
    "FLAG_ESCALATION_RECEIPT": "_apply_flag_escalation_receipt",
    "GOV_VOTING_CLOSE": "_apply_gov_voting_close",
    "GOV_TALLY_PUBLISH": "_apply_gov_tally_publish",
    "GOV_PROPOSAL_FINALIZE": "_apply_gov_proposal_finalize",
    "GOV_PROPOSAL_RECEIPT": "_apply_gov_proposal_receipt",
    "GROUP_UPDATE": "_apply_group_update",
    "GROUP_ROLE_GRANT": "_apply_group_role_grant",
    "GROUP_ROLE_REVOKE": "_apply_group_role_revoke",
    "GROUP_MEMBERSHIP_REQUEST": "_apply_group_membership_request",
    "GROUP_MEMBERSHIP_DECIDE": "_apply_group_membership_decide",
    "GROUP_MEMBERSHIP_REMOVE": "_apply_group_membership_remove",
    "GROUP_TREASURY_CREATE": "_apply_group_treasury_create",
    "GROUP_TREASURY_POLICY_SET": "_apply_group_treasury_policy_set",
    "GROUP_TREASURY_SPEND_PROPOSE": "_apply_group_treasury_spend_propose",
    "GROUP_TREASURY_SPEND_SIGN": "_apply_group_treasury_spend_sign",
    "GROUP_TREASURY_SPEND_CANCEL": "_apply_group_treasury_spend_cancel",
    "GROUP_TREASURY_SPEND_EXPIRE": "_apply_group_treasury_spend_expire",
    "GROUP_TREASURY_SPEND_EXECUTE": "_apply_group_treasury_spend_execute",
    "GROUP_TREASURY_AUDIT_ANCHOR_SET": "_apply_group_treasury_audit_anchor_set",
    "NODE_OPERATOR_PERFORMANCE_REPORT": "_apply_node_operator_performance_report",
    "CREATOR_PERFORMANCE_REPORT": "_apply_creator_performance_report",
    "PERFORMANCE_EVALUATE": "_apply_performance_evaluate",
    "PERFORMANCE_SCORE_APPLY": "_apply_performance_score_apply",
    "RATE_LIMIT_POLICY_SET": "_apply_rate_limit_policy_set",
    "RATE_LIMIT_STRIKE_APPLY": "_apply_rate_limit_strike_apply",
    "MEMPOOL_REJECT_RECEIPT": "_apply_mempool_reject_receipt",
    "CASE_TYPE_REGISTER": "_apply_case_type_register",
    "CASE_BIND_TO_DISPUTE": "_apply_case_bind_to_dispute",
    "CASE_OUTCOME_RECEIPT": "_apply_case_outcome_receipt",
}


def main() -> None:
    if not DOMAIN_APPLY.exists():
        raise SystemExit(f"domain_apply not found at {DOMAIN_APPLY}")

    src = DOMAIN_APPLY.read_text(encoding="utf-8")

    # Insert block once (right before _normalize_tags, stable anchor)
    if BEGIN not in src:
        anchor = "def _normalize_tags("
        pos = src.find(anchor)
        if pos < 0:
            raise SystemExit("Could not find insertion anchor: def _normalize_tags(")
        src = src[:pos] + INSERT_BLOCK + "\n\n" + src[pos:]

    # Rewire each branch that returns _apply_canon_missing(...)
    def rewire(text: str, tx_type: str, fn: str) -> str:
        # match:
        #   if t == "X":
        #       return _apply_canon_missing(ledger_state, env)
        pat = re.compile(
            rf'(if t == "{re.escape(tx_type)}":\s*\n\s*)return _apply_canon_missing\(([^)]*)\)',
            re.M,
        )
        return pat.sub(rf"\1return {fn}(\2)", text)

    out = src
    for tx, fn in REWIRES.items():
        out = rewire(out, tx, fn)

    DOMAIN_APPLY.write_text(out, encoding="utf-8")
    print(f"Patched: {DOMAIN_APPLY}")


if __name__ == "__main__":
    main()

