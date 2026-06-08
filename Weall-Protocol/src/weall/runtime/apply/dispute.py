# src/weall/runtime/apply/dispute.py
from __future__ import annotations

"""Dispute state transitions.

This module contains deterministic apply semantics for dispute-related tx types.
The canonical runtime dispatcher delegates to `apply_dispute()`
so we can keep the codebase maintainable.

This module raises DisputeApplyError (instead of ApplyError) so it can remain
standalone and not import the legacy monolith. The router translates
DisputeApplyError into ApplyError to preserve error codes and failure semantics.
"""

from dataclasses import dataclass
from typing import Any

from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.constitutional_clock import policy_from_state
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

_ALLOWED_DISPUTE_TARGET_TYPES = frozenset({
    "content",
    "post",
    "comment",
    "account",
    "group",
    "membership",
    "moderator",
    "reviewer",
    "poh",
})

_ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES = frozenset({
    "CONTENT_LABEL_SET",
    "CONTENT_VISIBILITY_SET",
    "CONTENT_THREAD_LOCK_SET",
    "ACCOUNT_LOCK",  # legacy queue-bound account action preserved for compatibility
    "ACCOUNT_RESTRICTION_SET",
    "GROUP_MEMBERSHIP_RESTRICT",
})


def _dispute_enforcement_rejections(state: Json) -> list[Json]:
    root = state.get("dispute_enforcement_rejections")
    if not isinstance(root, list):
        root = []
        state["dispute_enforcement_rejections"] = root
    return root


def _validate_dispute_target_type(target_type: str) -> str:
    t = _as_str(target_type).strip().lower()
    if not t or t not in _ALLOWED_DISPUTE_TARGET_TYPES:
        raise DisputeApplyError(
            "forbidden",
            "unsupported_dispute_target_type",
            {"target_type": target_type, "allowed": sorted(_ALLOWED_DISPUTE_TARGET_TYPES)},
        )
    return t


def _validate_dispute_enforcement_actions(state: Json, *, actions: list[Json], dispute_id: str, parent_ref: str | None) -> list[Json]:
    valid: list[Json] = []
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            _dispute_enforcement_rejections(state).append({
                "dispute_id": dispute_id,
                "index": int(index),
                "reason": "action_not_object",
                "parent": parent_ref or "",
            })
            continue
        tx_type = _as_str(action.get("tx_type")).strip().upper()
        if tx_type not in _ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES:
            _dispute_enforcement_rejections(state).append({
                "dispute_id": dispute_id,
                "index": int(index),
                "tx_type": tx_type,
                "reason": "unsupported_enforcement_action",
                "parent": parent_ref or "",
            })
            continue
        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        valid.append({"tx_type": tx_type, "payload": dict(payload)})
    return valid


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


def _eligible_key_for_actor(d: Json, juror: str) -> str:
    variants = set(_identity_variants(juror))
    for source_key in ("assigned_jurors", "eligible_juror_ids"):
        values = d.get(source_key)
        if not isinstance(values, list):
            continue
        for candidate in values:
            candidate_s = _as_str(candidate).strip()
            if candidate_s and variants.intersection(_identity_variants(candidate_s)):
                return candidate_s
    return ""


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
        if tx_type in {"CONTENT_LABEL_SET", "CONTENT_VISIBILITY_SET", "CONTENT_THREAD_LOCK_SET"}:
            env = _system_env(tx_type, payload, height=int(current_height), parent_ref=parent_ref)
            apply_content(state, env)
            applied.append({"tx_type": tx_type, "payload": dict(payload)})
            continue

        if tx_type == "ACCOUNT_RESTRICTION_SET":
            account_id = _as_str(payload.get("account_id") or payload.get("target_account") or payload.get("target_id")).strip()
            restriction = _as_str(payload.get("restriction") or payload.get("status") or "restricted_by_dispute").strip()
            if not account_id:
                continue
            accounts = state.get("accounts")
            if not isinstance(accounts, dict):
                accounts = {}
                state["accounts"] = accounts
            rec = accounts.get(account_id) if isinstance(accounts.get(account_id), dict) else {}
            restrictions = rec.get("restrictions") if isinstance(rec.get("restrictions"), list) else []
            entry = {
                "restriction": restriction,
                "reason": _as_str(payload.get("reason") or "dispute_enforcement"),
                "dispute_parent": parent_ref or "",
                "height": int(current_height),
            }
            if entry not in restrictions:
                restrictions.append(entry)
            rec["restrictions"] = restrictions
            rec["restricted"] = True
            rec["latest_restriction"] = restriction
            accounts[account_id] = rec
            applied.append({"tx_type": tx_type, "payload": dict(payload), "applied_to": account_id})
            continue

        if tx_type == "GROUP_MEMBERSHIP_RESTRICT":
            group_id = _as_str(payload.get("group_id") or payload.get("target_id")).strip()
            account_id = _as_str(payload.get("account_id") or payload.get("member") or payload.get("target_account")).strip()
            if not group_id or not account_id:
                continue
            groups = state.get("groups")
            if not isinstance(groups, dict):
                groups = {}
                state["groups"] = groups
            by_id = groups.get("by_id") if isinstance(groups.get("by_id"), dict) else {}
            groups["by_id"] = by_id
            grec = by_id.get(group_id) if isinstance(by_id.get(group_id), dict) else {"group_id": group_id}
            restricted = grec.get("restricted_members") if isinstance(grec.get("restricted_members"), dict) else {}
            restricted[account_id] = {
                "reason": _as_str(payload.get("reason") or "dispute_enforcement"),
                "height": int(current_height),
                "dispute_parent": parent_ref or "",
            }
            grec["restricted_members"] = restricted
            by_id[group_id] = grec
            applied.append({"tx_type": tx_type, "payload": dict(payload), "applied_to": account_id})
            continue
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
    yes = int(tally.get("yes", 0) or 0)
    no = int(tally.get("no", 0) or 0)
    report_upheld = yes > no

    # Resolution is derived from the final tally, not from whichever juror's
    # optional resolution object sorts first. This prevents a losing or stale
    # client-supplied action list from removing content when the report was not
    # upheld, and guarantees that an upheld content report receives the canonical
    # visibility enforcement action.
    selected_resolution = _select_resolution_from_votes(active_votes)
    resolution = dict(selected_resolution) if isinstance(selected_resolution, dict) else {}
    resolution["tally"] = dict(tally)
    resolution["eligible_validator_count"] = int(eligible_count)
    resolution["required_votes"] = int(required_votes)
    resolution["total_votes"] = int(total_votes)
    resolution["outcome"] = "report_upheld" if report_upheld else "report_not_upheld"

    is_content_target = (
        _as_str(dispute.get("target_type")).strip().lower() == "content"
        and bool(_as_str(dispute.get("target_id")).strip())
    )
    if is_content_target:
        selected_actions = resolution.get("actions") if isinstance(resolution.get("actions"), list) else []
        non_content_actions = [
            a for a in selected_actions
            if isinstance(a, dict)
            and _as_str(a.get("tx_type")).strip() not in {"CONTENT_LABEL_SET", "CONTENT_VISIBILITY_SET", "CONTENT_THREAD_LOCK_SET"}
        ]
        if report_upheld:
            resolution["summary"] = "Report upheld. The content should be removed."
            resolution["actions"] = _default_content_resolution_actions(dispute, dict(tally)) + non_content_actions
        else:
            resolution["summary"] = "Report not upheld. The content should remain visible."
            resolution["actions"] = []
    else:
        resolution.setdefault("summary", "deterministic validator-threshold resolution")
        actions = resolution.get("actions") if isinstance(resolution.get("actions"), list) else []
        if not actions and report_upheld:
            default_actions = _default_content_resolution_actions(dispute, dict(tally))
            if default_actions:
                resolution["actions"] = list(default_actions)

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


def _content_target_owner(state: Json, *, target_type: str, target_id: str) -> str:
    """Return the creator/owner of a disputed content target when known."""

    if _as_str(target_type).strip().lower() not in {"content", "post", "comment"}:
        return ""
    tid = _as_str(target_id).strip()
    if not tid:
        return ""
    content = state.get("content")
    if not isinstance(content, dict):
        return ""
    for bucket_name in ("posts", "comments"):
        bucket = content.get(bucket_name)
        if not isinstance(bucket, dict):
            continue
        rec = bucket.get(tid)
        if not isinstance(rec, dict):
            continue
        return _as_str(
            rec.get("author")
            or rec.get("owner")
            or rec.get("account_id")
            or rec.get("created_by")
            or rec.get("signer")
            or ""
        ).strip()
    return ""


def _same_account(a: str, b: str) -> bool:
    aa = _as_str(a).strip()
    bb = _as_str(b).strip()
    if not aa or not bb:
        return False
    return aa == bb or aa.lstrip("@") == bb.lstrip("@")


def _appeal_allowed_accounts(state: Json, d: Json) -> list[str]:
    raw = d.get("appeal_allowed_accounts")
    out: list[str] = []
    if isinstance(raw, list):
        out.extend(_as_str(x).strip() for x in raw if _as_str(x).strip())
    owner = _as_str(d.get("target_owner") or d.get("target_author") or "").strip()
    if not owner:
        owner = _content_target_owner(
            state,
            target_type=_as_str(d.get("target_type") or "content"),
            target_id=_as_str(d.get("target_id") or ""),
        )
    if owner:
        out.append(owner)
    seen: set[str] = set()
    normalized: list[str] = []
    for acct in out:
        key = acct.lstrip("@")
        if key in seen:
            continue
        seen.add(key)
        normalized.append(acct)
    return normalized


def _require_dispute_appeal_actor(state: Json, d: Json, signer: str) -> None:
    """Appeals are for the person directly affected by the outcome.

    For content moderation outcomes, that is the content creator/owner, not the
    reviewer who voted on the report and not every Tier 2 account that can see
    the appeal window.  Older non-content dispute records without an owner keep
    their historical permissive behavior until a dedicated subject field exists.
    """

    allowed = _appeal_allowed_accounts(state, d)
    if not allowed:
        return
    if not any(_same_account(signer, acct) for acct in allowed):
        raise DisputeApplyError(
            "forbidden",
            "appeal_not_target_owner",
            {"dispute_id": _as_str(d.get("id") or d.get("dispute_id")), "signer": signer, "allowed_accounts": allowed},
        )


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_disputes(state: Json) -> Json:
    return _ensure_root_dict(state, "disputes_by_id")


def _constitutional_clock_enabled(state: Json) -> bool:
    return bool(policy_from_state(state).enabled)


def _appeal_window_blocks(d: Json, *, default: int = 72) -> int:
    rules = _as_dict(d.get("rules"))
    try:
        return max(1, int(d.get("appeal_window_blocks", rules.get("appeal_window_blocks", default))))
    except Exception:
        return int(default)


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
    target_type = _validate_dispute_target_type(target_type)

    disputes = _ensure_disputes(state)
    if dispute_id in disputes:
        raise DisputeApplyError("duplicate", "dispute_id_exists", {"dispute_id": dispute_id})

    fallback_signer = "" if bool(getattr(env, "system", False)) or _as_str(env.signer).strip().upper() == "SYSTEM" else str(env.signer)
    eligible_jurors = _dispute_eligible_juror_ids(state, {"opened_by": env.signer}, fallback_signer)

    target_owner = _content_target_owner(state, target_type=target_type, target_id=target_id)
    disputes[dispute_id] = {
        "id": dispute_id,
        "stage": "open",
        "opened_by": env.signer,
        "opened_at_nonce": int(env.nonce),
        "target_type": target_type,
        "target_id": target_id,
        "target_owner": target_owner or None,
        "appeal_allowed_accounts": [target_owner] if target_owner else [],
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
    if not isinstance(jurors.get(juror_key), dict):
        eligible_key = _eligible_key_for_actor(d, env.signer)
        if not eligible_key:
            # Recompute the deterministic eligibility snapshot with the signer
            # as the bootstrap fallback.  SYSTEM-created report escalations can
            # reach the accept action before the queued assignment receipt has
            # surfaced, but the accept tx should still be able to materialize
            # the caller's own assignment if the committed dispute policy permits it.
            eligible_now = _dispute_eligible_juror_ids(state, d, env.signer)
            signer_variants = set(_identity_variants(env.signer))
            for candidate in eligible_now:
                candidate_s = _as_str(candidate).strip()
                if candidate_s and signer_variants.intersection(_identity_variants(candidate_s)):
                    eligible_key = candidate_s
                    break
        if eligible_key:
            juror_key = eligible_key
            jurors[juror_key] = {"status": "assigned", "assigned_at_nonce": int(env.nonce), "source": "eligible_juror_ids"}
            d["jurors"] = jurors
            assigned = _normalized_str_list(list(jurors.keys()))
            d["assigned_jurors"] = list(assigned)
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

    appeal_panel_result = _maybe_record_appeal_panel_vote(state, d, env, payload, juror_key)

    parent_ref = env.parent or _as_str(payload.get("_parent_ref")).strip() or f"tx:{env.signer}:{int(env.nonce)}"
    _maybe_schedule_dispute_auto_resolution(
        state,
        d,
        dispute_id,
        current_height=int(state.get("height", 0) or 0),
        parent_ref=parent_ref,
    )

    out: Json = {"applied": "DISPUTE_VOTE_SUBMIT", "dispute_id": dispute_id}
    if appeal_panel_result is not None:
        out["appeal_panel_result"] = appeal_panel_result
    return out



def _maybe_record_appeal_panel_vote(state: Json, d: Json, env: TxEnvelope, payload: Json, juror_key: str) -> Json | None:
    """Record deterministic appeal-panel votes using existing DISPUTE_VOTE_SUBMIT.

    Batch 508 avoids adding a new transaction type.  During appeal review, the
    same assigned/accepted juror path can submit an appeal decision.  Once the
    configured dispute quorum is reached, a canonical panel result is derived and
    later consumed by DISPUTE_FINAL_RECEIPT if no explicit system
    appeal_resolution is supplied.
    """

    stage = _as_str(d.get("stage") or "").strip().lower()
    appeal_resolution = payload.get("appeal_resolution") if isinstance(payload.get("appeal_resolution"), dict) else None
    raw_decision = _as_str(
        payload.get("appeal_decision")
        or payload.get("appeal_vote")
        or (appeal_resolution or {}).get("decision")
        or (appeal_resolution or {}).get("outcome")
        or ""
    ).strip().lower()
    if stage not in {"appealed", "appeal_review"} and not raw_decision:
        return None
    if raw_decision not in {"uphold", "reverse", "modify"}:
        return None

    panel_votes = d.get("appeal_panel_votes")
    if not isinstance(panel_votes, dict):
        panel_votes = {}
    vote_entry: Json = {
        "decision": raw_decision,
        "at_nonce": int(env.nonce),
        "height": int(state.get("height", 0) or 0),
    }
    if isinstance(appeal_resolution, dict):
        vote_entry["resolution"] = dict(appeal_resolution)
    summary = _as_str(payload.get("summary") or (appeal_resolution or {}).get("summary") or "").strip()
    if summary:
        vote_entry["summary"] = summary
    panel_votes[juror_key] = vote_entry
    d["appeal_panel_votes"] = panel_votes
    d["stage"] = "appeal_review"

    eligible = _dispute_eligible_juror_ids(state, d, str(env.signer))
    required = int(d.get("required_votes") or 0)
    if required <= 0:
        required = int(quorum_threshold(len(eligible))) if eligible else 1
    counts: dict[str, int] = {"uphold": 0, "reverse": 0, "modify": 0}
    for vote in panel_votes.values():
        if isinstance(vote, dict):
            decision = _as_str(vote.get("decision") or "").strip().lower()
            if decision in counts:
                counts[decision] += 1
    decision = ""
    for candidate in ("reverse", "modify", "uphold"):
        if counts.get(candidate, 0) >= required:
            decision = candidate
            break
    result: Json = {
        "votes": len(panel_votes),
        "required_votes": int(required),
        "counts": counts,
        "reached": bool(decision),
    }
    if decision:
        resolution: Json = {"decision": decision}
        # Deterministic tie-break for supplemental resolution details: use the
        # lexicographically first juror key that voted for the winning decision.
        for key in sorted(panel_votes):
            vote = panel_votes.get(key)
            if not isinstance(vote, dict) or _as_str(vote.get("decision") or "").strip().lower() != decision:
                continue
            if isinstance(vote.get("resolution"), dict):
                resolution.update(dict(vote["resolution"]))
                resolution["decision"] = decision
            if _as_str(vote.get("summary") or "").strip():
                resolution.setdefault("summary", _as_str(vote.get("summary")).strip())
            break
        result["decision"] = decision
        result["resolution"] = resolution
        d["appeal_panel_result"] = result
    else:
        d["appeal_panel_result"] = result
    return result

def _apply_dispute_resolve(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    d["resolved"] = True
    d["resolution"] = payload.get("resolution")
    d["resolved_at_nonce"] = int(env.nonce)

    # Constitutional-clock testnet mode makes dispute finality appealable.
    # The resolution/verdict is recorded now, but final receipt/enforcement is
    # delayed until the deterministic appeal window closes or the appeal path
    # is resolved. Legacy/dev flows keep the historical immediate final receipt.
    constitutional_appeal_mode = _constitutional_clock_enabled(state)
    if constitutional_appeal_mode:
        try:
            verdict_h = int(payload.get("_due_height") or state.get("height") or 0)
        except Exception:
            verdict_h = int(state.get("height", 0) or 0)
        d["stage"] = "appeal_window"
        d["verdict_at_height"] = int(verdict_h)
        d["resolved_at_height"] = int(verdict_h)
        d["appeal_window_blocks"] = int(_appeal_window_blocks(d))
        d["appeal_deadline_height"] = int(verdict_h) + int(_appeal_window_blocks(d))
    else:
        d["stage"] = "resolved"

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

    # 1) Emit DISPUTE_FINAL_RECEIPT immediately only in legacy/dev mode.
    # Constitutional-clock mode delays final receipt until the appeal window closes.
    if not constitutional_appeal_mode:
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
        if isinstance(actions, list) and not constitutional_appeal_mode:
            valid_actions = _validate_dispute_enforcement_actions(state, actions=[a for a in actions if isinstance(a, dict)], dispute_id=dispute_id, parent_ref=parent_ref)
            applied_actions = _apply_inline_content_enforcement(
                state,
                actions=valid_actions,
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
            for a in valid_actions:
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
    stage = _as_str(d.get("stage")).strip().lower()
    if _constitutional_clock_enabled(state):
        if stage not in {"appeal_window", "appealed", "appeal_review"}:
            raise DisputeApplyError("forbidden", "appeal_window_not_open", {"dispute_id": dispute_id, "stage": stage})
        deadline = int(d.get("appeal_deadline_height") or 0)
        current_h = int(state.get("height", 0) or 0)
        if deadline > 0 and current_h > deadline:
            raise DisputeApplyError("forbidden", "appeal_window_closed", {"dispute_id": dispute_id, "deadline_height": deadline, "height": current_h})
    _require_dispute_appeal_actor(state, d, _as_str(env.signer).strip())
    appeals = d.get("appeals")
    if not isinstance(appeals, list):
        appeals = []
    appeals.append({"by": env.signer, "at_nonce": int(env.nonce), "height": int(state.get("height", 0) or 0), "payload": payload})
    d["appeals"] = appeals
    d["stage"] = "appealed"
    return {"applied": "DISPUTE_APPEAL", "dispute_id": dispute_id}


def _final_receipt_resolution(dispute: Json, payload: Json) -> tuple[Json, Json]:
    """Return the effective final resolution and appeal metadata.

    Constitutional-clock disputes delay enforcement until final receipt.  If an
    appeal was submitted, a system final receipt may carry an ``appeal_resolution``
    object with a deterministic decision.  ``reverse`` suppresses original
    enforcement actions; ``modify`` uses the appeal-provided actions; ``uphold``
    keeps the original resolution unless replacement actions are supplied.
    """

    original = payload.get("resolution") if isinstance(payload.get("resolution"), dict) else dispute.get("resolution")
    resolution: Json = dict(original) if isinstance(original, dict) else {}
    appeal_resolution = payload.get("appeal_resolution")
    if not isinstance(appeal_resolution, dict):
        appeal_resolution = {}
    if not appeal_resolution:
        panel_result = dispute.get("appeal_panel_result")
        if isinstance(panel_result, dict) and bool(panel_result.get("reached")) and isinstance(panel_result.get("resolution"), dict):
            appeal_resolution = dict(panel_result["resolution"])
            appeal_resolution.setdefault("source", "appeal_panel")

    appeals = dispute.get("appeals") if isinstance(dispute.get("appeals"), list) else []
    appeal_meta: Json = {
        "appealed": bool(appeals),
        "appeal_count": len(appeals),
        "decision": "none",
    }
    if appeal_resolution:
        decision = _as_str(appeal_resolution.get("decision") or appeal_resolution.get("outcome") or "uphold").strip().lower()
        if decision not in {"uphold", "reverse", "modify"}:
            decision = "uphold"
        appeal_meta["decision"] = decision
        appeal_meta["resolution"] = dict(appeal_resolution)
        if decision == "reverse":
            resolution["appeal_decision"] = "reverse"
            resolution["actions"] = []
            resolution["summary"] = _as_str(appeal_resolution.get("summary") or "Appeal reversed the dispute outcome.")
        elif decision == "modify":
            resolution.update({k: v for k, v in appeal_resolution.items() if k != "decision"})
            resolution["appeal_decision"] = "modify"
        else:
            replacement_actions = appeal_resolution.get("actions")
            if isinstance(replacement_actions, list):
                resolution["actions"] = replacement_actions
            if _as_str(appeal_resolution.get("summary")):
                resolution["summary"] = _as_str(appeal_resolution.get("summary"))
            resolution["appeal_decision"] = "uphold"
    elif appeals:
        appeal_meta["decision"] = "pending_review"

    return resolution, appeal_meta


def _apply_dispute_final_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    # Keep a light receipt surface for audits
    root = _ensure_root_dict(state, "dispute_receipts")
    rid = _mk_id("receipt", env, payload.get("receipt_id") or payload.get("id"))
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    applied_actions: list[Json] = []
    appeal_meta: Json = {"appealed": False, "decision": "none", "appeal_count": 0}
    final_resolution: Json = payload.get("resolution") if isinstance(payload.get("resolution"), dict) else {}

    if dispute_id:
        d = _get_dispute(state, dispute_id)
        final_resolution, appeal_meta = _final_receipt_resolution(d, payload)
        d["final_resolution"] = dict(final_resolution)
        d["appeal_finalization"] = dict(appeal_meta)
        # If an appeal exists but no appeal decision has been supplied, do not
        # silently finalize enforcement.  Keep the case in appeal review and
        # record an audit receipt for the attempted finalization.
        if appeal_meta.get("decision") == "pending_review":
            d["stage"] = "appeal_review"
        else:
            parent_ref = _as_str(payload.get("_parent_ref") or env.parent or f"tx:{env.signer}:{int(env.nonce)}").strip()
            actions = final_resolution.get("actions") if isinstance(final_resolution.get("actions"), list) else []
            valid_actions = _validate_dispute_enforcement_actions(state, actions=[a for a in actions if isinstance(a, dict)], dispute_id=dispute_id, parent_ref=parent_ref)
            applied_actions = _apply_inline_content_enforcement(
                state,
                actions=valid_actions,
                current_height=int(state.get("height", 0) or 0),
                parent_ref=parent_ref,
            )
            d["stage"] = "finalized"
            d["finalized_at_nonce"] = int(env.nonce)
            d["final_enforcement_applied"] = list(applied_actions)

    if rid not in root:
        root[rid] = {
            "receipt_id": rid,
            "tx_type": str(env.tx_type or ""),
            "at_nonce": int(env.nonce),
            "payload": payload,
            "resolution": dict(final_resolution),
            "appeal_finalization": dict(appeal_meta),
            "enforcement_applied": list(applied_actions),
        }
    return {
        "applied": "DISPUTE_FINAL_RECEIPT",
        "receipt_id": rid,
        "receipt": True,
        "appeal_finalization": appeal_meta,
        "enforcement_applied": applied_actions,
    }


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
