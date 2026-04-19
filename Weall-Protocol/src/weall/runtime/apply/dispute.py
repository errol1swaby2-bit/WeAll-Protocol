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
from typing import Any

from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


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


def _normalized_str_list(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        s = _as_str(item).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return out


def _identity_variants(value: Any) -> list[str]:
    s = _as_str(value).strip()
    if not s:
        return []
    base = s[1:] if s.startswith("@") else s
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (s, base, f"@{base}" if base else ""):
        c = _as_str(candidate).strip()
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _resolve_account_identity(state: Json, value: Any) -> str:
    variants = _identity_variants(value)
    if not variants:
        return ""
    accounts = _as_dict(state.get("accounts"))
    for variant in variants:
        if variant in accounts:
            return variant
    return variants[0]


def _alias_record(mapping: Any, identity: str) -> dict[str, Any] | None:
    if not isinstance(mapping, dict):
        return None
    for variant in _identity_variants(identity):
        rec = mapping.get(variant)
        if isinstance(rec, dict):
            return rec
    return None


def _canonical_actor_key(active_identities: list[str], signer: str, state: Json) -> str:
    variants = set(_identity_variants(signer))
    for identity in active_identities:
        if variants.intersection(_identity_variants(identity)):
            return identity
    return _resolve_account_identity(state, signer)


def _juror_key_for_actor(d: Json, juror: str) -> str:
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
        d["jurors"] = jurors
    for variant in _identity_variants(juror):
        if variant in jurors:
            return variant
    assigned = d.get("assigned_jurors")
    if isinstance(assigned, list):
        variants = set(_identity_variants(juror))
        for candidate in assigned:
            candidate_s = _as_str(candidate).strip()
            if candidate_s and variants.intersection(_identity_variants(candidate_s)):
                return candidate_s
    return _as_str(juror).strip()


def _active_validator_ids(state: Json) -> list[str]:
    roles = _as_dict(state.get("roles"))
    validators = _as_dict(roles.get("validators"))
    active_set = _normalized_str_list([_resolve_account_identity(state, item) for item in _normalized_str_list(validators.get("active_set"))])
    if active_set:
        return active_set

    validators_by_id = _as_dict(validators.get("by_id"))
    if validators_by_id:
        out: list[str] = []
        for acct, rec in validators_by_id.items():
            acct_s = _as_str(acct).strip()
            if not acct_s or not isinstance(rec, dict):
                continue
            status = _as_str(rec.get("status")).strip().lower()
            if status and status not in {"active", "activated", "validator"}:
                continue
            out.append(_resolve_account_identity(state, acct_s))
        out = sorted(set(out))
        if out:
            return out

    consensus = _as_dict(state.get("consensus"))
    validator_set = _as_dict(consensus.get("validator_set"))
    active_set = _normalized_str_list([_resolve_account_identity(state, item) for item in _normalized_str_list(validator_set.get("active_set"))])
    if active_set:
        return active_set

    registry = _as_dict(_as_dict(consensus.get("validators")).get("registry"))
    if registry:
        out: list[str] = []
        for acct, rec in registry.items():
            acct_s = _as_str(acct).strip()
            if not acct_s or not isinstance(rec, dict):
                continue
            status = _as_str(rec.get("status")).strip().lower()
            if status and status not in {"active", "activated", "validator"}:
                continue
            out.append(_resolve_account_identity(state, acct_s))
        out = sorted(set(out))
        if out:
            return out
    return []


def _dispute_eligible_juror_ids(state: Json, dispute: Json, fallback_signer: str = "") -> list[str]:
    snap = _normalized_str_list([_resolve_account_identity(state, item) for item in _normalized_str_list(dispute.get("eligible_juror_ids"))])
    if snap:
        dispute["eligible_juror_ids"] = list(snap)
        dispute["eligible_validator_count"] = int(len(snap))
        dispute["required_votes"] = int(quorum_threshold(len(snap))) if snap else 0
        return snap

    assigned = _normalized_str_list([_resolve_account_identity(state, item) for item in _normalized_str_list(dispute.get("assigned_jurors"))])
    if assigned:
        dispute["eligible_juror_ids"] = list(assigned)
        dispute["eligible_validator_count"] = int(len(assigned))
        dispute["required_votes"] = int(quorum_threshold(len(assigned))) if assigned else 0
        return assigned

    active = _active_validator_ids(state)
    if active:
        dispute["eligible_juror_ids"] = list(active)
        dispute["eligible_validator_count"] = int(len(active))
        dispute["required_votes"] = int(quorum_threshold(len(active))) if active else 0
        return active

    raw_signer = fallback_signer or dispute.get("opened_by")
    signer = _resolve_account_identity(state, raw_signer)
    if signer and signer.upper() != "SYSTEM":
        dispute["eligible_juror_ids"] = [signer]
        dispute["eligible_validator_count"] = 1
        dispute["required_votes"] = 1
        return [signer]

    dispute["eligible_juror_ids"] = []
    dispute["eligible_validator_count"] = 0
    dispute["required_votes"] = 0
    return []


def _active_validator_vote_snapshot(state: Json, votes: Any, eligible_override: list[str] | None = None) -> tuple[dict[str, dict[str, Any]], int, int]:
    votes_d = votes if isinstance(votes, dict) else {}
    eligible = _normalized_str_list(eligible_override) if isinstance(eligible_override, list) and eligible_override else _active_validator_ids(state)
    eligible_count = len(eligible)
    required_votes = quorum_threshold(eligible_count) if eligible_count > 0 else 0
    active_votes: dict[str, dict[str, Any]] = {}
    for acct in eligible:
        rec = _alias_record(votes_d, acct)
        if isinstance(rec, dict):
            active_votes[acct] = rec
    return active_votes, eligible_count, required_votes


def _vote_choice_tally(votes: dict[str, dict[str, Any]]) -> dict[str, int]:
    tally = {"yes": 0, "no": 0, "abstain": 0}
    for rec in votes.values():
        choice = _as_str(rec.get("vote") or rec.get("choice")).strip().lower()
        if choice in tally:
            tally[choice] += 1
    return tally


def _select_resolution_from_votes(votes: dict[str, dict[str, Any]]) -> Json:
    for signer in sorted(votes.keys()):
        rec = votes.get(signer)
        if not isinstance(rec, dict):
            continue
        resolution = rec.get("resolution")
        if isinstance(resolution, dict) and resolution:
            return dict(resolution)
    return {}


def _system_env(tx_type: str, payload: Json, *, height: int, parent_ref: str | None) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM",
        nonce=int(height),
        payload=dict(payload),
        system=True,
        parent=parent_ref,
    )


def _default_content_resolution_actions(dispute: Json, tally: Json) -> list[Json]:
    target_id = _as_str(dispute.get("target_id")).strip()
    if _as_str(dispute.get("target_type")).strip().lower() != "content" or not target_id:
        return []

    yes = int(tally.get("yes", 0) or 0)
    no = int(tally.get("no", 0) or 0)
    if yes <= no:
        return []

    actions: list[Json] = [
        {
            "tx_type": "CONTENT_LABEL_SET",
            "payload": {
                "target_id": target_id,
                "labels": ["dispute_upheld", "policy_violation"],
            },
        },
        {
            "tx_type": "CONTENT_VISIBILITY_SET",
            "payload": {
                "target_id": target_id,
                "visibility": "deleted",
            },
        },
    ]
    if target_id.startswith("post:"):
        actions.append(
            {
                "tx_type": "CONTENT_THREAD_LOCK_SET",
                "payload": {"target_id": target_id, "locked": True},
            }
        )
    return actions



def _apply_inline_content_enforcement(state: Json, *, actions: list[Json], current_height: int, parent_ref: str | None) -> list[Json]:
    if not actions:
        return []
    applied: list[Json] = []
    from weall.runtime.apply.content import apply_content  # local import avoids circular import

    for action in actions:
        if not isinstance(action, dict):
            continue
        tx_type = _as_str(action.get("tx_type")).strip()
        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        if tx_type not in {"CONTENT_LABEL_SET", "CONTENT_VISIBILITY_SET", "CONTENT_THREAD_LOCK_SET"}:
            continue
        env = _system_env(tx_type, payload, height=int(current_height), parent_ref=parent_ref)
        apply_content(state, env)
        applied.append({"tx_type": tx_type, "payload": dict(payload)})
    return applied



def _maybe_schedule_dispute_auto_resolution(state: Json, dispute: Json, dispute_id: str, *, current_height: int, parent_ref: str | None) -> None:
    if bool(dispute.get("resolved")) or _as_str(dispute.get("stage")).strip().lower() == "resolved":
        return

    eligible_jurors = _dispute_eligible_juror_ids(state, dispute)
    active_votes, eligible_count, required_votes = _active_validator_vote_snapshot(state, dispute.get("votes"), eligible_jurors)
    total_votes = len(active_votes)
    if required_votes <= 0:
        fallback_votes = dispute.get("votes") if isinstance(dispute.get("votes"), dict) else {}
        if not fallback_votes:
            return
        active_votes = {str(k): v for k, v in fallback_votes.items() if isinstance(v, dict)}
        eligible_count = len(active_votes)
        required_votes = len(active_votes)
        total_votes = len(active_votes)
    if required_votes <= 0 or total_votes < required_votes:
        return

    tally = _vote_choice_tally(active_votes)
    resolution = _select_resolution_from_votes(active_votes)
    if not resolution:
        resolution = {
            "summary": "deterministic validator-threshold resolution",
            "tally": dict(tally),
            "eligible_validator_count": int(eligible_count),
            "required_votes": int(required_votes),
            "total_votes": int(total_votes),
        }
    else:
        resolution = dict(resolution)
        resolution.setdefault("tally", dict(tally))
        resolution.setdefault("eligible_validator_count", int(eligible_count))
        resolution.setdefault("required_votes", int(required_votes))
        resolution.setdefault("total_votes", int(total_votes))

    actions = resolution.get("actions") if isinstance(resolution.get("actions"), list) else []
    if not actions:
        actions = _default_content_resolution_actions(dispute, dict(tally))
        if actions:
            resolution["actions"] = list(actions)

    payload: Json = {"dispute_id": dispute_id, "resolution": resolution}
    if parent_ref:
        payload["_parent_ref"] = parent_ref

    _apply_dispute_resolve(state, _system_env("DISPUTE_RESOLVE", payload, height=int(current_height), parent_ref=parent_ref))


def _mk_id(prefix: str, env: TxEnvelope, provided: object) -> str:
    s = _as_str(provided).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{env.nonce}"


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise DisputeApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _require_assigned_juror(d: Json, juror: str) -> Json:
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
        d["jurors"] = jurors
    juror_key = _juror_key_for_actor(d, juror)
    j = jurors.get(juror_key)
    if not isinstance(j, dict):
        raise DisputeApplyError(
            "forbidden",
            "juror_not_assigned",
            {"dispute_id": d.get("id", ""), "juror": juror},
        )
    if juror_key != juror:
        jurors[juror_key] = j
        d["jurors"] = jurors
    return j


def _require_juror_status(d: Json, juror: str, allowed: set[str]) -> Json:
    j = _require_assigned_juror(d, juror)
    status = _as_str(j.get("status")).strip().lower()
    allowed_l = {s.lower() for s in allowed}
    if status not in allowed_l:
        raise DisputeApplyError(
            "forbidden",
            "juror_wrong_status",
            {
                "dispute_id": d.get("id", ""),
                "juror": juror,
                "status": status,
                "allowed": sorted(list(allowed_l)),
            },
        )
    return j


def _index_dispute_target(state: Json, d: Json) -> None:
    tgt_type = _as_str(d.get("target_type")).strip()
    tgt_id = _as_str(d.get("target_id")).strip()
    did = _as_str(d.get("id")).strip()
    if not tgt_type or not tgt_id or not did:
        return
    idx = state.get("disputes_by_target")
    if not isinstance(idx, dict):
        idx = {}
        state["disputes_by_target"] = idx
    idx[f"{tgt_type}:{tgt_id}"] = did


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

    fallback_signer = "" if bool(getattr(env, "system", False)) or _as_str(env.signer).strip().upper() == "SYSTEM" else str(env.signer)
    eligible_jurors = _dispute_eligible_juror_ids(state, {"opened_by": env.signer}, fallback_signer)

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
        "eligible_juror_ids": list(eligible_jurors),
        "eligible_validator_count": int(len(eligible_jurors)),
        "required_votes": int(quorum_threshold(len(eligible_jurors))) if eligible_jurors else 0,
        "resolved": False,
        "resolution": None,
        "appeals": [],
    }
    _index_dispute_target(state, disputes[dispute_id])
    return {"applied": "DISPUTE_OPEN", "dispute_id": dispute_id}


def _apply_dispute_stage_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    stage = _as_str(payload.get("stage")).strip()
    if not dispute_id or not stage:
        raise DisputeApplyError(
            "invalid_payload", "missing_dispute_or_stage", {"tx_type": env.tx_type}
        )
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
        raise DisputeApplyError(
            "invalid_payload", "missing_dispute_or_evidence_id", {"tx_type": env.tx_type}
        )
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
    return {
        "applied": "DISPUTE_EVIDENCE_BIND",
        "dispute_id": dispute_id,
        "evidence_id": evidence_id,
    }


def _apply_dispute_juror_assign(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    juror = _as_str(payload.get("juror") or payload.get("juror_id")).strip()
    if not dispute_id or not juror:
        raise DisputeApplyError(
            "invalid_payload", "missing_dispute_or_juror", {"tx_type": env.tx_type}
        )
    d = _get_dispute(state, dispute_id)
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    eligible_jurors = _dispute_eligible_juror_ids(state, d, juror)
    juror_key = _canonical_actor_key(eligible_jurors, juror, state)
    jurors[juror_key] = {"status": "assigned", "assigned_at_nonce": int(env.nonce)}
    d["jurors"] = jurors
    assigned = _normalized_str_list(list(_as_dict(d.get("jurors")).keys()))
    d["assigned_jurors"] = list(assigned)
    d["eligible_juror_ids"] = list(assigned or eligible_jurors)
    d["eligible_validator_count"] = int(len(d["eligible_juror_ids"]))
    d["required_votes"] = int(quorum_threshold(len(d["eligible_juror_ids"]))) if d["eligible_juror_ids"] else 0
    stage = _as_str(d.get("stage")).strip().lower()
    if stage in {"", "open"}:
        d["stage"] = "juror_review"
        d["stage_set_at_nonce"] = int(env.nonce)
    return {"applied": "DISPUTE_JUROR_ASSIGN", "dispute_id": dispute_id, "juror": juror_key}


def _apply_dispute_juror_accept(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
        d["jurors"] = jurors
    juror_key = _juror_key_for_actor(d, env.signer)
    j = _require_assigned_juror(d, env.signer)
    status = _as_str(j.get("status")).strip().lower()
    if status in {"accepted", "attended", "present"}:
        jurors[juror_key] = j
        d["jurors"] = jurors
        return {"applied": "DISPUTE_JUROR_ACCEPT", "dispute_id": dispute_id, "status": status or "accepted", "idempotent": True}
    if status not in {"", "assigned"}:
        raise DisputeApplyError(
            "forbidden",
            "juror_wrong_status",
            {
                "dispute_id": d.get("id", ""),
                "juror": env.signer,
                "status": status,
                "allowed": ["assigned", "accepted"],
            },
        )
    j["status"] = "accepted"
    j["accepted_at_nonce"] = int(env.nonce)
    j["attendance"] = {"present": True, "at_nonce": int(env.nonce), "auto": True, "source": "accept"}
    jurors[juror_key] = j
    d["jurors"] = jurors
    return {"applied": "DISPUTE_JUROR_ACCEPT", "dispute_id": dispute_id, "present": True}


def _apply_dispute_juror_decline(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
        d["jurors"] = jurors
    juror_key = _juror_key_for_actor(d, env.signer)
    j = _require_assigned_juror(d, env.signer)
    j["status"] = "declined"
    j["declined_at_nonce"] = int(env.nonce)
    jurors[juror_key] = j
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
    juror_key = _juror_key_for_actor(d, env.signer)
    j = _require_juror_status(d, env.signer, {"assigned", "accepted"})
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    j = jurors.get(juror_key) if isinstance(jurors.get(juror_key), dict) else j
    if not isinstance(j, dict):
        j = {"status": "accepted"}
    status = _as_str(j.get("status")).strip().lower()
    if status in {"", "assigned"}:
        j["status"] = "accepted"
        j.setdefault("accepted_at_nonce", int(env.nonce))
    j["attendance"] = {"present": present, "at_nonce": int(env.nonce)}
    jurors[juror_key] = j
    d["jurors"] = jurors
    return {"applied": "DISPUTE_JUROR_ATTENDANCE", "dispute_id": dispute_id, "present": present}


def _apply_dispute_vote_submit(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    _dispute_eligible_juror_ids(state, d, env.signer)
    juror_key = _juror_key_for_actor(d, env.signer)
    j = _require_juror_status(d, env.signer, {"assigned", "accepted"})
    status = _as_str(j.get("status")).strip().lower()
    if status in {"", "assigned"}:
        j["status"] = "accepted"
        j.setdefault("accepted_at_nonce", int(env.nonce))
        jurors = d.get("jurors")
        if not isinstance(jurors, dict):
            jurors = {}
            d["jurors"] = jurors
        jurors[juror_key] = j
    att = j.get("attendance")
    if isinstance(att, dict) and not bool(att.get("present", False)):
        raise DisputeApplyError(
            "forbidden", "juror_not_present", {"dispute_id": dispute_id, "juror": env.signer}
        )
    votes = d.get("votes")
    if not isinstance(votes, dict):
        votes = {}
    resolution = payload.get("resolution") if isinstance(payload.get("resolution"), dict) else None
    vote_entry: Json = {"vote": payload.get("vote"), "at_nonce": int(env.nonce)}
    if isinstance(resolution, dict) and resolution:
        vote_entry["resolution"] = dict(resolution)
    for alias in _identity_variants(env.signer):
        if alias != juror_key:
            votes.pop(alias, None)
    votes[juror_key] = vote_entry
    d["votes"] = votes

    parent_ref = env.parent or _as_str(payload.get("_parent_ref")).strip() or f"tx:{env.signer}:{int(env.nonce)}"
    _maybe_schedule_dispute_auto_resolution(
        state,
        d,
        dispute_id,
        current_height=int(state.get("height", 0) or 0),
        parent_ref=parent_ref,
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
    parent_ref = (
        _as_str(payload.get("_system_queue_id") or "").strip()
        or f"tx:{env.signer}:{int(env.nonce)}"
    )

    # 1) Always emit DISPUTE_FINAL_RECEIPT for audits.
    enqueue_system_tx(
        state,
        tx_type="DISPUTE_FINAL_RECEIPT",
        payload={
            "dispute_id": dispute_id,
            "resolution": payload.get("resolution") or {},
            "_parent_ref": parent_ref,
        },
        due_height=due_height,
        signer="SYSTEM",
        once=True,
        parent=parent_ref,
        phase="post",
    )

    # 2) Optional enforcement actions. Apply content moderation actions inline so
    # the visible target state changes deterministically with dispute resolution,
    # then queue any remaining non-content/system follow-ups for the next height.
    res = payload.get("resolution")
    applied_actions: list[Json] = []
    queued_actions: list[Json] = []
    if isinstance(res, dict):
        actions = res.get("actions")
        if isinstance(actions, list):
            applied_actions = _apply_inline_content_enforcement(
                state,
                actions=[a for a in actions if isinstance(a, dict)],
                current_height=int(base_due_h),
                parent_ref=parent_ref,
            )
            applied_keys = {
                (
                    _as_str(a.get("tx_type")).strip(),
                    _as_str((a.get("payload") if isinstance(a.get("payload"), dict) else {}).get("target_id") or (a.get("payload") if isinstance(a.get("payload"), dict) else {}).get("id")).strip(),
                )
                for a in applied_actions
            }
            for a in actions:
                if not isinstance(a, dict):
                    continue
                tx_type = _as_str(a.get("tx_type") or "").strip()
                pl = a.get("payload") if isinstance(a.get("payload"), dict) else {}
                if not tx_type:
                    continue
                key = (tx_type, _as_str(pl.get("target_id") or pl.get("id")).strip())
                if key in applied_keys:
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
                queued_actions.append({"tx_type": tx_type, "payload": dict(pl)})

    return {"applied": "DISPUTE_RESOLVE", "dispute_id": dispute_id, "enforcement_applied": applied_actions, "enforcement_queued": queued_actions}


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
        root[rid] = {
            "receipt_id": rid,
            "tx_type": str(env.tx_type or ""),
            "at_nonce": int(env.nonce),
            "payload": payload,
        }
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
        case_type = _as_str(
            payload.get("case_type") or payload.get("type") or payload.get("name")
        ).strip()
        if not case_type:
            raise DisputeApplyError("invalid_payload", "missing_case_type", {"tx_type": t})
        types = cases["types"]
        if case_type not in types:
            types[case_type] = {
                "case_type": case_type,
                "registered_at_nonce": int(env.nonce),
                "payload": payload,
            }
        return {"applied": t, "case_type": case_type, "receipt": True}

    if t == "CASE_BIND_TO_DISPUTE":
        case_id = (
            _as_str(payload.get("case_id") or payload.get("id")).strip() or f"case:{env.nonce}"
        )
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


DISPUTE_TX_TYPES: set[str] = {
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


def apply_dispute(state: Json, env: TxEnvelope) -> Json | None:
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
