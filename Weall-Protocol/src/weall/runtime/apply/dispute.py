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

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any

from weall.runtime.ballot_policy import ballot_profile_status, strict_civic_governance_enabled
from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.constitutional_clock import policy_from_state
from weall.runtime.poh.state import effective_poh_tier
from weall.runtime.reputation_events import append_reputation_event
from weall.runtime.reviewer_responsibilities import (
    CONTENT_REVIEW_LANE,
    DISPUTE_REVIEW_LANE,
    eligible_reviewer_ids,
    reviewer_lane_active,
)
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission import TxEnvelope
from weall.util.ipfs_cid import validate_ipfs_cid

Json = dict[str, Any]


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _require_active_dispute_ballot_profile(state: Json, *, dispute_id: str, stage: str) -> Json:
    status = ballot_profile_status(state)
    if bool(status.get("strict")) and not bool(status.get("active")):
        raise DisputeApplyError(
            "forbidden",
            "ballot_profile_inactive",
            {
                "dispute_id": dispute_id,
                "stage": stage,
                "profile_id": status.get("profile_id"),
                "profile_reason": status.get("reason"),
            },
        )
    return status


def _dispute_ballot_receipts(state: Json) -> list[Json]:
    receipts = state.get("dispute_ballot_admission_receipts")
    if not isinstance(receipts, list):
        receipts = []
        state["dispute_ballot_admission_receipts"] = receipts
    return receipts


def _dispute_ballot_nullifier(
    *, dispute_id: str, panel_round: int, juror: str, appeal: bool
) -> str:
    return _canonical_hash(
        {
            "domain": "weall.dispute.ballot-nullifier.v1",
            "dispute_id": _as_str(dispute_id).strip(),
            "panel_round": int(panel_round),
            "ballot_class": "appeal" if appeal else "review",
            "juror": _as_str(juror).strip(),
        }
    )


def _aggregate_dispute_counts(dispute: Json, *, appeal: bool = False) -> dict[str, int]:
    key = "appeal_vote_counts" if appeal else "vote_counts"
    raw = dispute.get(key)
    counts: dict[str, int] = {}
    if isinstance(raw, dict):
        for choice, count in raw.items():
            choice_s = _as_str(choice).strip().lower()
            if not choice_s:
                continue
            counts[choice_s] = max(0, _as_int(count, 0))
    dispute[key] = counts
    return counts


def _dispute_ballot_nullifiers(dispute: Json, *, appeal: bool = False) -> dict[str, Json]:
    key = "appeal_ballot_nullifiers" if appeal else "ballot_nullifiers"
    raw = dispute.get(key)
    nullifiers = raw if isinstance(raw, dict) else {}
    dispute[key] = nullifiers
    return nullifiers


def _dispute_voted_juror_ids(dispute: Json, *, appeal: bool = False) -> list[str]:
    key = "appeal_voted_juror_ids" if appeal else "voted_juror_ids"
    raw = dispute.get(key)
    values = sorted({_as_str(item).strip() for item in raw if _as_str(item).strip()}) if isinstance(raw, list) else []
    dispute[key] = values
    return values


def _record_deattributed_resolution_option(
    dispute: Json,
    *,
    choice: str,
    resolution: Json | None,
    summary: str = "",
    appeal: bool = False,
) -> None:
    if not resolution and not summary:
        return
    key = "appeal_resolution_options" if appeal else "resolution_options"
    raw = dispute.get(key)
    options = raw if isinstance(raw, dict) else {}
    normalized_resolution = dict(resolution) if isinstance(resolution, dict) else {}
    option_payload = {
        "choice": _as_str(choice).strip().lower(),
        "resolution": normalized_resolution,
        "summary": _as_str(summary).strip(),
    }
    commitment = _canonical_hash(
        {"domain": "weall.dispute.deattributed-resolution-option.v1", **option_payload}
    )
    existing = options.get(commitment)
    count = _as_int(existing.get("count"), 0) if isinstance(existing, dict) else 0
    options[commitment] = {**option_payload, "count": int(count + 1)}
    dispute[key] = options


def _select_deattributed_resolution(dispute: Json, *, winning_choice: str, appeal: bool = False) -> Json:
    key = "appeal_resolution_options" if appeal else "resolution_options"
    options = dispute.get(key)
    if not isinstance(options, dict):
        return {}
    matching: list[tuple[str, Json]] = []
    for commitment, rec in options.items():
        if not isinstance(rec, dict):
            continue
        if _as_str(rec.get("choice")).strip().lower() != _as_str(winning_choice).strip().lower():
            continue
        matching.append((_as_str(commitment), rec))
    if not matching:
        return {}
    # Prefer the most frequently submitted option; break ties by commitment.
    matching.sort(key=lambda item: (-_as_int(item[1].get("count"), 0), item[0]))
    selected = matching[0][1]
    out = dict(selected.get("resolution")) if isinstance(selected.get("resolution"), dict) else {}
    summary = _as_str(selected.get("summary")).strip()
    if summary:
        out.setdefault("summary", summary)
    return out


@dataclass
class DisputeApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


_ALLOWED_DISPUTE_TARGET_TYPES = frozenset(
    {
        "content",
        "post",
        "comment",
        "account",
        "group",
        "membership",
        "moderator",
        "reviewer",
        "poh",
    }
)

_ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES = frozenset(
    {
        "CONTENT_LABEL_SET",
        "CONTENT_VISIBILITY_SET",
        "CONTENT_THREAD_LOCK_SET",
        "ACCOUNT_LOCK",  # legacy queue-bound account action preserved for compatibility
        "ACCOUNT_REINSTATE",
        "ACCOUNT_RESTRICTION_SET",
        "GROUP_MEMBERSHIP_RESTRICT",
        "ROLE_ELIGIBILITY_SET",
        "ROLE_JUROR_REINSTATE",
    }
)


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


def _validate_dispute_enforcement_actions(
    state: Json, *, actions: list[Json], dispute_id: str, parent_ref: str | None
) -> list[Json]:
    valid: list[Json] = []
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            _dispute_enforcement_rejections(state).append(
                {
                    "dispute_id": dispute_id,
                    "index": int(index),
                    "reason": "action_not_object",
                    "parent": parent_ref or "",
                }
            )
            continue
        tx_type = _as_str(action.get("tx_type")).strip().upper()
        if tx_type not in _ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES:
            _dispute_enforcement_rejections(state).append(
                {
                    "dispute_id": dispute_id,
                    "index": int(index),
                    "tx_type": tx_type,
                    "reason": "unsupported_enforcement_action",
                    "parent": parent_ref or "",
                }
            )
            continue
        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        valid.append({"tx_type": tx_type, "payload": dict(payload)})
    return valid


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _require_public_cid(value: Any, *, field: str, tx_type: str) -> str:
    cid = _as_str(value).strip()
    if not cid:
        return ""
    check = validate_ipfs_cid(cid)
    if not check.ok:
        raise DisputeApplyError(
            "invalid_payload",
            "invalid_public_cid",
            {"field": field, "cid": cid, "reason": check.reason, "tx_type": tx_type},
        )
    return cid


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


def _dispute_target_owner(state: Json, d: Json) -> str:
    owner = _as_str(d.get("target_owner") or d.get("target_author") or "").strip()
    if owner:
        return _resolve_account_identity(state, owner)
    owner = _content_target_owner(
        state,
        target_type=_as_str(d.get("target_type") or "content"),
        target_id=_as_str(d.get("target_id") or ""),
    )
    return _resolve_account_identity(state, owner) if owner else ""


def _is_dispute_target_owner(state: Json, d: Json, account: str) -> bool:
    owner = _dispute_target_owner(state, d)
    return bool(owner and _same_account(owner, _as_str(account).strip()))


def _filter_target_owner_from_jurors(state: Json, d: Json, jurors: list[str]) -> list[str]:
    owner = _dispute_target_owner(state, d)
    target_type = _as_str(d.get("target_type") or "").strip().lower()
    content_review_target = target_type in {"", "content", "post", "comment"}
    filtered: list[str] = []
    excluded: list[str] = []
    for juror in _normalized_str_list([_resolve_account_identity(state, item) for item in jurors]):
        if owner and _same_account(owner, juror):
            excluded.append(juror)
            continue
        filtered.append(juror)
    if owner:
        d["target_owner"] = owner
    if owner and content_review_target:
        # Record the content-review conflict policy whenever a content/post/comment
        # dispute has a known owner, even if that owner was never present in the
        # active reviewer candidate set. This keeps read models truthful after the
        # stricter explicit-reviewer opt-in filter removes non-reviewers earlier.
        d["conflict_policy"] = "target_owner_excluded_from_content_review"
    if excluded:
        existing = _normalized_str_list(d.get("conflicted_juror_ids"))
        d["conflicted_juror_ids"] = _normalized_str_list(existing + excluded)
    return filtered


def _dispute_conflict_account_ids(state: Json, dispute: Json) -> list[str]:
    conflicts: list[str] = []
    for value in (
        dispute.get("reported_by"),
        dispute.get("flagged_by"),
        dispute.get("reporter"),
        dispute.get("opened_by"),
        _dispute_target_owner(state, dispute),
    ):
        resolved = _resolve_account_identity(state, value)
        if resolved and resolved.upper() != "SYSTEM":
            conflicts.append(resolved)

    for key in (
        "party_ids",
        "parties",
        "beneficiary_ids",
        "conflicted_account_ids",
        "material_connection_ids",
        "financial_connection_ids",
    ):
        raw = dispute.get(key)
        if isinstance(raw, list):
            conflicts.extend(_resolve_account_identity(state, item) for item in raw)

    rules = _as_dict(dispute.get("rules"))
    raw_rule_conflicts = rules.get("conflicted_account_ids")
    if isinstance(raw_rule_conflicts, list):
        conflicts.extend(_resolve_account_identity(state, item) for item in raw_rule_conflicts)

    target_type = _as_str(dispute.get("target_type")).strip().lower()
    group_id = _as_str(dispute.get("group_id") or (dispute.get("target_id") if target_type in {"group", "membership", "moderator"} else "")).strip()
    if group_id:
        roles = _as_dict(state.get("roles"))
        groups = roles.get("groups_by_id") if isinstance(roles.get("groups_by_id"), dict) else state.get("groups_by_id")
        group = groups.get(group_id) if isinstance(groups, dict) else None
        if isinstance(group, dict):
            for role_key in ("creator", "creators", "admin", "admins", "moderator", "moderators", "emissary", "emissaries", "signers"):
                raw = group.get(role_key)
                if isinstance(raw, list):
                    conflicts.extend(_resolve_account_identity(state, item) for item in raw)
                elif isinstance(raw, dict):
                    conflicts.extend(_resolve_account_identity(state, item) for item in raw.keys())
                elif raw:
                    conflicts.append(_resolve_account_identity(state, raw))
            role_map = group.get("roles")
            if isinstance(role_map, dict):
                for role_key in ("creator", "creators", "admin", "admins", "moderator", "moderators", "emissary", "emissaries"):
                    raw = role_map.get(role_key)
                    if isinstance(raw, list):
                        conflicts.extend(_resolve_account_identity(state, item) for item in raw)
                    elif isinstance(raw, dict):
                        conflicts.extend(_resolve_account_identity(state, item) for item in raw.keys())

    return _normalized_str_list([item for item in conflicts if item])


def _dispute_panel_size(dispute: Json) -> int:
    raw = _as_str(dispute.get("severity") or _as_dict(dispute.get("rules")).get("severity") or "low").strip().lower()
    if raw in {"critical", "severe", "high", "major"}:
        return 25
    if raw in {"medium", "moderate", "elevated"}:
        return 15
    return 7


def select_dispute_panel(
    state: Json,
    dispute: Json,
    candidates: list[str],
    *,
    round_no: int = 1,
    exclude_ids: list[str] | None = None,
) -> Json:
    """Select a deterministic constitutional review panel.

    Strict M3 profiles require the complete 7/15/25 panel plus ceil(20%)
    substitutes. Legacy/local fixtures keep their historical all-reviewer
    behavior so unrelated development paths are not silently reinterpreted.
    """

    normalized = _normalized_str_list(
        [_resolve_account_identity(state, item) for item in candidates]
    )
    conflicts = set(_dispute_conflict_account_ids(state, dispute))
    excluded = set(_normalized_str_list(exclude_ids or [])) | conflicts
    eligible = [item for item in normalized if item not in excluded]

    strict = strict_civic_governance_enabled(state)
    required_panel = _dispute_panel_size(dispute)
    substitute_count = int(math.ceil(required_panel * 0.20))
    seed = {
        "domain": "weall.dispute.panel.v1",
        "chain_id": _as_str(state.get("chain_id") or _as_dict(state.get("params")).get("chain_id")),
        "dispute_id": _as_str(dispute.get("id") or dispute.get("dispute_id")),
        "target_type": _as_str(dispute.get("target_type")),
        "target_id": _as_str(dispute.get("target_id")),
        "opened_at_height": _as_int(dispute.get("opened_at_height"), 0),
        "round": int(round_no),
        "candidate_commitment": _canonical_hash(sorted(eligible)),
    }
    ordered = sorted(
        eligible,
        key=lambda account: (_canonical_hash({**seed, "candidate": account}), account),
    )

    if not strict:
        panel = ordered
        substitutes: list[str] = []
        status = "legacy_all_eligible_reviewers"
    elif len(ordered) < required_panel + substitute_count:
        panel = []
        substitutes = []
        status = "insufficient_reviewer_pool"
    else:
        panel = ordered[:required_panel]
        substitutes = ordered[required_panel : required_panel + substitute_count]
        status = "assigned"

    commitment_payload = {
        **seed,
        "required_panel_size": int(required_panel),
        "required_substitute_count": int(substitute_count),
        "panel": panel,
        "substitutes": substitutes,
        "conflicts": sorted(conflicts),
        "status": status,
    }
    return {
        "round": int(round_no),
        "strict": bool(strict),
        "status": status,
        "required_panel_size": int(required_panel),
        "required_substitute_count": int(substitute_count),
        "available_candidate_count": int(len(ordered)),
        "panel": panel,
        "substitutes": substitutes,
        "conflicted_juror_ids": sorted(conflicts),
        "excluded_juror_ids": sorted(excluded),
        "candidate_commitment": seed["candidate_commitment"],
        "panel_commitment": _canonical_hash(commitment_payload),
    }


def repair_unassigned_dispute_panels(state: Json, *, next_height: int) -> int:
    """Assign complete strict-profile panels after the reviewer pool grows.

    This is called from the shared leader/replay scheduler pipeline. It replaces
    the legacy one-reviewer opt-in shortcut with a deterministic assignment that
    every node can reproduce from canonical reviewer state.
    """

    if not strict_civic_governance_enabled(state):
        return 0
    disputes = state.get("disputes_by_id")
    if not isinstance(disputes, dict):
        return 0
    receipts = state.get("dispute_panel_assignment_receipts")
    if not isinstance(receipts, list):
        receipts = []
        state["dispute_panel_assignment_receipts"] = receipts

    repaired = 0
    for dispute_id in sorted(disputes):
        dispute = disputes.get(dispute_id)
        if not isinstance(dispute, dict):
            continue
        stage = _as_str(dispute.get("stage")).strip().lower()
        if stage not in {"unassigned", "open", "juror_review"}:
            continue
        if _normalized_str_list(dispute.get("assigned_jurors")):
            continue
        target_type = _as_str(dispute.get("target_type")).strip().lower()
        lane = (
            CONTENT_REVIEW_LANE
            if target_type in {"", "content", "post", "comment", "media"}
            else DISPUTE_REVIEW_LANE
        )
        candidates = eligible_reviewer_ids(state, lane)
        round_no = max(1, _as_int(dispute.get("panel_round"), 1))
        selection = select_dispute_panel(
            state,
            dispute,
            candidates,
            round_no=round_no,
        )
        dispute["panel_status"] = selection["status"]
        dispute["panel_commitment"] = selection["panel_commitment"]
        dispute["panel_required_size"] = selection["required_panel_size"]
        dispute["substitute_required_count"] = selection["required_substitute_count"]
        dispute["substitute_juror_ids"] = list(selection["substitutes"])
        dispute["conflicted_juror_ids"] = list(selection["conflicted_juror_ids"])
        panel = list(selection["panel"])
        if not panel:
            dispute["stage"] = "unassigned"
            dispute["assignment_blocked_reason"] = "insufficient_constitutional_reviewer_pool"
            disputes[dispute_id] = dispute
            continue

        dispute["eligible_juror_ids"] = list(panel)
        dispute["assigned_jurors"] = list(panel)
        dispute["eligible_validator_count"] = int(len(panel))
        dispute["required_votes"] = int(quorum_threshold(len(panel)))
        dispute["stage"] = "juror_review"
        dispute["stage_set_at_height"] = int(next_height)
        dispute["assignment_blocked_reason"] = ""
        jurors = dispute.get("jurors")
        if not isinstance(jurors, dict):
            jurors = {}
        for juror in panel:
            prior = jurors.get(juror) if isinstance(jurors.get(juror), dict) else {}
            jurors[juror] = {
                **prior,
                "status": "assigned",
                "assigned_at_height": int(next_height),
                "panel_round": int(round_no),
                "assignment_source": "deterministic_panel_repair",
            }
        dispute["jurors"] = jurors
        receipt = {
            "dispute_id": _as_str(dispute.get("id") or dispute_id),
            "height": int(next_height),
            "panel_round": int(round_no),
            "panel_commitment": selection["panel_commitment"],
            "panel": list(panel),
            "substitutes": list(selection["substitutes"]),
            "lane": lane,
        }
        receipts.append(receipt)
        disputes[dispute_id] = dispute
        repaired += 1
    return repaired


def _active_validator_ids(state: Json) -> list[str]:
    roles = _as_dict(state.get("roles"))
    validators = _as_dict(roles.get("validators"))
    active_set = _normalized_str_list(
        [
            _resolve_account_identity(state, item)
            for item in _normalized_str_list(validators.get("active_set"))
        ]
    )
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
    active_set = _normalized_str_list(
        [
            _resolve_account_identity(state, item)
            for item in _normalized_str_list(validator_set.get("active_set"))
        ]
    )
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


def _filter_active_dispute_reviewers(state: Json, jurors: list[str], dispute: Json) -> list[str]:
    active = [
        _resolve_account_identity(state, item)
        for item in _normalized_str_list(jurors)
        if reviewer_lane_active(state, _resolve_account_identity(state, item), DISPUTE_REVIEW_LANE)
    ]
    conflicts = set(_dispute_conflict_account_ids(state, dispute))
    filtered = [item for item in _normalized_str_list(active) if item not in conflicts]
    if conflicts:
        existing = _normalized_str_list(dispute.get("conflicted_juror_ids"))
        dispute["conflicted_juror_ids"] = _normalized_str_list(existing + sorted(conflicts))
        dispute["conflict_policy"] = "constitutional_material_conflicts_excluded"
    return filtered


def _require_dispute_reviewer_lane(
    state: Json, account_id: str, dispute: Json | None = None
) -> str:
    acct = _resolve_account_identity(state, account_id)
    if dispute is not None and acct and _is_dispute_target_owner(state, dispute, acct):
        # Preserve the more specific safety failure for conflicted content owners.
        # Responsibility opt-in is still enforced for every unconflicted reviewer.
        raise DisputeApplyError(
            "forbidden",
            "juror_conflict_target_owner",
            {"juror": acct, "target_owner": _dispute_target_owner(state, dispute)},
        )
    if not acct or not reviewer_lane_active(state, acct, DISPUTE_REVIEW_LANE):
        raise DisputeApplyError(
            "forbidden",
            "reviewer_responsibility_not_active",
            {"account_id": account_id, "lane": DISPUTE_REVIEW_LANE},
        )
    return acct


def _dispute_eligible_juror_ids(state: Json, dispute: Json, fallback_signer: str = "") -> list[str]:
    # Dispute review is a human-review responsibility. Validators, content
    # authors, reporters, or fallback signers never inherit this duty unless
    # they explicitly hold an active Juror/reviewer lane.
    stage = _as_str(dispute.get("stage")).strip().lower()
    if stage in {"appealed", "appeal_review"}:
        appeal_snap = _filter_active_dispute_reviewers(
            state,
            [
                _resolve_account_identity(state, item)
                for item in _normalized_str_list(dispute.get("appeal_panel_juror_ids"))
            ],
            dispute,
        )
        if appeal_snap:
            dispute["eligible_juror_ids"] = list(appeal_snap)
            dispute["eligible_validator_count"] = int(len(appeal_snap))
            dispute["required_votes"] = int(quorum_threshold(len(appeal_snap)))
            return appeal_snap

    snap = _filter_active_dispute_reviewers(
        state,
        [
            _resolve_account_identity(state, item)
            for item in _normalized_str_list(dispute.get("eligible_juror_ids"))
        ],
        dispute,
    )
    if snap:
        dispute["eligible_juror_ids"] = list(snap)
        dispute["eligible_validator_count"] = int(len(snap))
        dispute["required_votes"] = int(quorum_threshold(len(snap))) if snap else 0
        return snap

    assigned = _filter_active_dispute_reviewers(
        state,
        [
            _resolve_account_identity(state, item)
            for item in _normalized_str_list(dispute.get("assigned_jurors"))
        ],
        dispute,
    )
    if assigned:
        dispute["eligible_juror_ids"] = list(assigned)
        dispute["eligible_validator_count"] = int(len(assigned))
        dispute["required_votes"] = int(quorum_threshold(len(assigned))) if assigned else 0
        return assigned

    active = _filter_active_dispute_reviewers(
        state, eligible_reviewer_ids(state, DISPUTE_REVIEW_LANE), dispute
    )
    if active:
        dispute["eligible_juror_ids"] = list(active)
        dispute["eligible_validator_count"] = int(len(active))
        dispute["required_votes"] = int(quorum_threshold(len(active))) if active else 0
        return active

    if strict_civic_governance_enabled(state):
        dispute["eligible_juror_ids"] = []
        dispute["eligible_validator_count"] = 0
        dispute["required_votes"] = 0
        dispute["assignment_blocked_reason"] = "constitutional_panel_required"
        return []

    raw_signer = fallback_signer or dispute.get("opened_by")
    signer = _resolve_account_identity(state, raw_signer)
    if (
        signer
        and signer.upper() != "SYSTEM"
        and reviewer_lane_active(state, signer, DISPUTE_REVIEW_LANE)
        and not _is_dispute_target_owner(state, dispute, signer)
    ):
        dispute["eligible_juror_ids"] = [signer]
        dispute["eligible_validator_count"] = 1
        dispute["required_votes"] = 1
        return [signer]

    dispute["eligible_juror_ids"] = []
    dispute["eligible_validator_count"] = 0
    dispute["required_votes"] = 0
    return []


def _active_validator_vote_snapshot(
    state: Json, votes: Any, eligible_override: list[str] | None = None
) -> tuple[dict[str, dict[str, Any]], int, int]:
    votes_d = votes if isinstance(votes, dict) else {}
    eligible = (
        _normalized_str_list(eligible_override)
        if isinstance(eligible_override, list) and eligible_override
        else _active_validator_ids(state)
    )
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

    # Removal-by-review must not erase the target during the appealable phase.
    # The normal feed/read-model hides ``hidden`` targets just like removed
    # targets, while the underlying post/comment record remains available for
    # the dispute/appeal record and final review.  Final hard deletion can be a
    # later explicit enforcement policy, but the default due-process path is an
    # appeal quarantine.
    actions: list[Json] = [
        {
            "tx_type": "CONTENT_LABEL_SET",
            "payload": {
                "target_id": target_id,
                "labels": ["dispute_upheld", "policy_violation", "appeal_quarantined"],
            },
        },
        {
            "tx_type": "CONTENT_VISIBILITY_SET",
            "payload": {
                "target_id": target_id,
                "visibility": "hidden",
                "reason": "dispute_appeal_quarantine",
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


def _quarantine_content_enforcement_for_appeal_window(resolution: Any) -> Json:
    """Return a resolution whose content-removal actions preserve appealability.

    A report verdict may include legacy/client-supplied actions that say
    ``visibility=deleted``.  In constitutional appeal mode those actions must not
    mark the content record deleted before the affected creator can appeal.  The
    target is still removed from public/account/group feeds because ``hidden`` is
    treated as a moderation hide by the read model.
    """

    if not isinstance(resolution, dict):
        return {}
    out: Json = dict(resolution)
    actions = out.get("actions")
    if not isinstance(actions, list):
        return out

    normalized: list[Json] = []
    changed = False
    for action in actions:
        if not isinstance(action, dict):
            continue
        tx_type = _as_str(action.get("tx_type") or "").strip()
        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        next_action: Json = {"tx_type": tx_type, "payload": dict(payload)}

        if tx_type == "CONTENT_VISIBILITY_SET":
            visibility = _as_str(payload.get("visibility") or "").strip().lower()
            if visibility in {"deleted", "removed", "remove"}:
                next_payload = dict(payload)
                next_payload["visibility"] = "hidden"
                next_payload.pop("deleted", None)
                next_payload.setdefault("reason", "dispute_appeal_quarantine")
                next_action["payload"] = next_payload
                changed = True
        normalized.append(next_action)

    if changed:
        out["actions"] = normalized
        out["appeal_quarantine"] = {
            "active": True,
            "model": "hidden_not_deleted_until_appeal_finalization",
            "feed_visibility": "hidden",
            "content_record_retained": True,
        }
    return out


def _apply_inline_content_enforcement(
    state: Json, *, actions: list[Json], current_height: int, parent_ref: str | None
) -> list[Json]:
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
            account_id = _as_str(
                payload.get("account_id")
                or payload.get("target_account")
                or payload.get("target_id")
            ).strip()
            restriction = _as_str(
                payload.get("restriction") or payload.get("status") or "restricted_by_dispute"
            ).strip()
            if not account_id:
                continue
            accounts = state.get("accounts")
            if not isinstance(accounts, dict):
                accounts = {}
                state["accounts"] = accounts
            rec = accounts.get(account_id) if isinstance(accounts.get(account_id), dict) else {}
            restrictions = (
                rec.get("restrictions") if isinstance(rec.get("restrictions"), list) else []
            )
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

        if tx_type == "ACCOUNT_REINSTATE":
            account_id = _as_str(
                payload.get("account_id")
                or payload.get("target_account")
                or payload.get("target_id")
            ).strip()
            if not account_id:
                continue
            accounts = state.get("accounts")
            if not isinstance(accounts, dict):
                accounts = {}
                state["accounts"] = accounts
            rec = accounts.get(account_id) if isinstance(accounts.get(account_id), dict) else {}
            prior = {
                "restricted": bool(rec.get("restricted", False)),
                "locked": bool(rec.get("locked", False)),
                "banned": bool(rec.get("banned", False)),
                "latest_restriction": _as_str(rec.get("latest_restriction") or ""),
            }
            rec["restricted"] = False
            rec["locked"] = False
            rec["banned"] = False
            rec["latest_restriction"] = ""
            remedies = rec.get("remedies") if isinstance(rec.get("remedies"), list) else []
            remedy = {
                "remedy": "account_reinstated",
                "reason": _as_str(payload.get("reason") or "dispute_appeal_remedy"),
                "height": int(current_height),
                "dispute_parent": parent_ref or "",
                "prior": prior,
            }
            if remedy not in remedies:
                remedies.append(remedy)
            rec["remedies"] = remedies
            accounts[account_id] = rec
            applied.append(
                {
                    "tx_type": tx_type,
                    "payload": dict(payload),
                    "applied_to": account_id,
                    "remedy": "account_reinstated",
                }
            )
            continue

        if tx_type in {"ROLE_ELIGIBILITY_SET", "ROLE_JUROR_REINSTATE"}:
            account_id = _as_str(
                payload.get("account_id")
                or payload.get("target_account")
                or payload.get("target_id")
                or payload.get("juror_id")
            ).strip()
            role = (
                _as_str(
                    payload.get("role")
                    or ("dispute_juror" if tx_type == "ROLE_JUROR_REINSTATE" else "")
                ).strip()
                or "dispute_juror"
            )
            eligible = bool(payload.get("eligible", True))
            if not account_id:
                continue
            accounts = state.get("accounts")
            if not isinstance(accounts, dict):
                accounts = {}
                state["accounts"] = accounts
            rec = accounts.get(account_id) if isinstance(accounts.get(account_id), dict) else {}
            eligibility = (
                rec.get("role_eligibility") if isinstance(rec.get("role_eligibility"), dict) else {}
            )
            eligibility[role] = {
                "eligible": bool(eligible),
                "height": int(current_height),
                "reason": _as_str(payload.get("reason") or "dispute_appeal_remedy"),
                "dispute_parent": parent_ref or "",
            }
            rec["role_eligibility"] = eligibility
            if role in {"dispute_juror", "juror"}:
                rec["dispute_juror_eligible"] = bool(eligible)
                if bool(eligible):
                    rec.pop("dispute_juror_suspended_reason", None)
            if role in {"poh_reviewer", "reviewer"}:
                rec["poh_reviewer_eligible"] = bool(eligible)
                if bool(eligible):
                    rec.pop("poh_reviewer_suspended_reason", None)
            accounts[account_id] = rec
            applied.append(
                {
                    "tx_type": tx_type,
                    "payload": dict(payload),
                    "applied_to": account_id,
                    "role": role,
                    "eligible": bool(eligible),
                }
            )
            continue

        if tx_type == "GROUP_MEMBERSHIP_RESTRICT":
            group_id = _as_str(payload.get("group_id") or payload.get("target_id")).strip()
            account_id = _as_str(
                payload.get("account_id") or payload.get("member") or payload.get("target_account")
            ).strip()
            if not group_id or not account_id:
                continue
            groups = state.get("groups")
            if not isinstance(groups, dict):
                groups = {}
                state["groups"] = groups
            by_id = groups.get("by_id") if isinstance(groups.get("by_id"), dict) else {}
            groups["by_id"] = by_id
            grec = (
                by_id.get(group_id)
                if isinstance(by_id.get(group_id), dict)
                else {"group_id": group_id}
            )
            restricted = (
                grec.get("restricted_members")
                if isinstance(grec.get("restricted_members"), dict)
                else {}
            )
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


def _maybe_schedule_dispute_auto_resolution(
    state: Json, dispute: Json, dispute_id: str, *, current_height: int, parent_ref: str | None
) -> None:
    if bool(dispute.get("resolved")) or _as_str(dispute.get("stage")).strip().lower() == "resolved":
        return

    eligible_jurors = _dispute_eligible_juror_ids(state, dispute)
    strict_ballot = strict_civic_governance_enabled(state)
    if strict_ballot:
        tally = _aggregate_dispute_counts(dispute)
        eligible_count = len(eligible_jurors)
        required_votes = _as_int(dispute.get("required_votes"), 0)
        if required_votes <= 0 and eligible_count > 0:
            required_votes = int(quorum_threshold(eligible_count))
        total_votes = int(sum(tally.values()))
        active_votes: dict[str, dict[str, Any]] = {}
    else:
        active_votes, eligible_count, required_votes = _active_validator_vote_snapshot(
            state, dispute.get("votes"), eligible_jurors
        )
        total_votes = len(active_votes)
        if required_votes <= 0:
            fallback_votes = dispute.get("votes") if isinstance(dispute.get("votes"), dict) else {}
            if not fallback_votes:
                return
            active_votes = {str(k): v for k, v in fallback_votes.items() if isinstance(v, dict)}
            eligible_count = len(active_votes)
            required_votes = len(active_votes)
            total_votes = len(active_votes)
        tally = _vote_choice_tally(active_votes)
    if required_votes <= 0 or total_votes < required_votes:
        return

    yes = int(tally.get("yes", 0) or 0)
    no = int(tally.get("no", 0) or 0)
    report_upheld = yes > no

    # Resolution is derived from the final tally, not from whichever juror's
    # optional resolution object sorts first. This prevents a losing or stale
    # client-supplied action list from removing content when the report was not
    # upheld, and guarantees that an upheld content report receives the canonical
    # visibility enforcement action.
    selected_resolution = (
        _select_deattributed_resolution(
            dispute,
            winning_choice="yes" if report_upheld else "no",
        )
        if strict_ballot
        else _select_resolution_from_votes(active_votes)
    )
    resolution = dict(selected_resolution) if isinstance(selected_resolution, dict) else {}
    resolution["tally"] = dict(tally)
    resolution["eligible_validator_count"] = int(eligible_count)
    resolution["required_votes"] = int(required_votes)
    resolution["total_votes"] = int(total_votes)
    resolution["outcome"] = "report_upheld" if report_upheld else "report_not_upheld"

    is_content_target = _as_str(dispute.get("target_type")).strip().lower() == "content" and bool(
        _as_str(dispute.get("target_id")).strip()
    )
    if is_content_target:
        selected_actions = (
            resolution.get("actions") if isinstance(resolution.get("actions"), list) else []
        )
        non_content_actions = [
            a
            for a in selected_actions
            if isinstance(a, dict)
            and _as_str(a.get("tx_type")).strip()
            not in {"CONTENT_LABEL_SET", "CONTENT_VISIBILITY_SET", "CONTENT_THREAD_LOCK_SET"}
        ]
        if report_upheld:
            resolution["summary"] = "Report upheld. The content should be removed."
            resolution["actions"] = (
                _default_content_resolution_actions(dispute, dict(tally)) + non_content_actions
            )
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

    _apply_dispute_resolve(
        state,
        _system_env("DISPUTE_RESOLVE", payload, height=int(current_height), parent_ref=parent_ref),
    )


def _mk_id(prefix: str, env: TxEnvelope, provided: object) -> str:
    s = _as_str(provided).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{env.nonce}"


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise DisputeApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _current_height(state: Json) -> int:
    return _as_int(state.get("height"), 0)


def _dispute_reputation_params(state: Json, dispute: Json | None = None) -> Json:
    """Return deterministic dispute-juror reputation windows.

    Values are block counts, not local time.  Defaults assume the constitutional
    20-second clock: 180 blocks = 1 hour, 45 blocks = 15 minutes.
    """
    params = _as_dict(state.get("params"))
    rep = _as_dict(params.get("reputation"))
    dispute_params = _as_dict(rep.get("dispute"))
    top_dispute = _as_dict(params.get("dispute"))
    rules = _as_dict(_as_dict(dispute).get("rules")) if isinstance(dispute, dict) else {}

    def pick_int(key: str, default: int) -> int:
        for bucket in (rules, dispute_params, top_dispute, params):
            if key in bucket:
                return max(0, _as_int(bucket.get(key), default))
        return int(default)

    vote_window = pick_int("juror_vote_window_blocks", pick_int("vote_window_blocks", 180))
    safe_withdraw = pick_int("safe_withdraw_blocks", 45)
    if vote_window <= 0:
        vote_window = 180
    if safe_withdraw <= 0:
        safe_withdraw = 45
    if safe_withdraw > vote_window:
        safe_withdraw = vote_window
    return {
        "vote_window_blocks": int(vote_window),
        "safe_withdraw_blocks": int(safe_withdraw),
        "late_withdraw_penalty_milli": -max(0, pick_int("late_withdraw_penalty_milli", 500)),
        "timeout_penalty_milli": -max(0, pick_int("timeout_penalty_milli", 1500)),
    }


def _ensure_juror_deadlines(
    state: Json, dispute: Json, juror_record: Json, *, accepted_height: int
) -> Json:
    params = _dispute_reputation_params(state, dispute)
    vote_window = int(params["vote_window_blocks"])
    safe_window = int(params["safe_withdraw_blocks"])
    juror_record["accepted_at_height"] = int(accepted_height)
    juror_record.setdefault("accepted_at_block_height", int(accepted_height))
    juror_record["vote_deadline_height"] = int(accepted_height) + vote_window
    juror_record["safe_withdraw_until_height"] = int(accepted_height) + safe_window
    juror_record["reputation_policy"] = {
        "version": 1,
        "clock": "block_height",
        "vote_window_blocks": vote_window,
        "safe_withdraw_blocks": safe_window,
        "late_withdraw_penalty_milli": int(params["late_withdraw_penalty_milli"]),
        "timeout_penalty_milli": int(params["timeout_penalty_milli"]),
    }
    return juror_record


def _juror_has_vote(dispute: Json, juror: str) -> bool:
    variants = set(_identity_variants(juror))
    voted = dispute.get("voted_juror_ids")
    if isinstance(voted, list):
        for voter in voted:
            if variants.intersection(_identity_variants(voter)):
                return True
    votes = _as_dict(dispute.get("votes"))
    return any(_as_str(voter).strip() in variants for voter in votes.keys())


def _record_dispute_juror_reputation_event(
    state: Json,
    *,
    dispute_id: str,
    juror: str,
    event_type: str,
    delta_milli: int,
    at_height: int,
    at_nonce: int,
    reason: str,
    visibility: str = "public",
) -> Json:
    root = state.get("dispute_juror_reputation_events")
    if not isinstance(root, dict):
        root = {}
        state["dispute_juror_reputation_events"] = root
    event_id = f"dispute-juror-rep:v1:{dispute_id}:{juror}:{event_type}"
    existing = root.get(event_id)
    if isinstance(existing, dict):
        return dict(existing, deduped=True)
    rep_event = append_reputation_event(
        state,
        actor_id=juror,
        event_code=event_type,
        source_flow="dispute",
        source_tx_id=f"dispute:{dispute_id}:{event_type}:{at_nonce}",
        source_object_id=f"{dispute_id}:{juror}",
        delta=int(delta_milli),
        occurred_at_block=int(at_height),
        occurred_at_time=int(at_height),
        details={"dispute_id": dispute_id, "reason": reason, "legacy_event_id": event_id},
    )
    rec: Json = {
        "event_id": event_id,
        "canonical_reputation_event_id": rep_event.get("event_id"),
        "dispute_id": dispute_id,
        "juror": juror,
        "account_id": juror,
        "event_type": event_type,
        "delta_milli": int(delta_milli),
        "at_height": int(at_height),
        "at_nonce": int(at_nonce),
        "reason": reason,
        "visibility": visibility,
        "deterministic": True,
        "clock": "block_height",
        "version": 1,
        "deduped": False,
    }
    root[event_id] = rec
    return rec


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
            {
                "dispute_id": _as_str(d.get("id") or d.get("dispute_id")),
                "signer": signer,
                "allowed_accounts": allowed,
            },
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
        return max(
            1, int(d.get("appeal_window_blocks", rules.get("appeal_window_blocks", default)))
        )
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
    if not bool(getattr(env, "system", False)) and effective_poh_tier(state, str(env.signer)) < 1:
        raise DisputeApplyError(
            "forbidden", "tier1_required_for_dispute", {"account": str(env.signer)}
        )
    if target_type in {"proposal", "governance", "governance_proposal"}:
        proposals = state.get("gov_proposals_by_id")
        proposal = proposals.get(target_id) if isinstance(proposals, dict) else None
        if not isinstance(proposal, dict):
            raise DisputeApplyError("not_found", "proposal_not_found", {"target_id": target_id})
        proposal_status = _as_str(proposal.get("status") or proposal.get("stage")).strip().lower()
        if proposal_status not in {
            "finalized",
            "executed",
            "rejected",
            "expired",
            "cancelled",
            "closed",
        }:
            raise DisputeApplyError(
                "forbidden",
                "active_proposal_dispute_protected",
                {"target_id": target_id, "status": proposal_status},
            )

    disputes = _ensure_disputes(state)
    if dispute_id in disputes:
        raise DisputeApplyError("duplicate", "dispute_id_exists", {"dispute_id": dispute_id})

    fallback_signer = (
        ""
        if bool(getattr(env, "system", False)) or _as_str(env.signer).strip().upper() == "SYSTEM"
        else str(env.signer)
    )
    eligible_jurors = _dispute_eligible_juror_ids(state, {"opened_by": env.signer}, fallback_signer)

    target_owner = _content_target_owner(state, target_type=target_type, target_id=target_id)
    reported_by = _as_str(
        payload.get("reported_by") or payload.get("flagged_by") or payload.get("reporter") or ""
    ).strip()
    opened_h = _current_height(state)
    disputes[dispute_id] = {
        "id": dispute_id,
        "stage": "open",
        "opened_by": env.signer,
        "reported_by": reported_by or None,
        "flagged_by": reported_by or None,
        "opened_at_nonce": int(env.nonce),
        "opened_at_height": int(opened_h),
        "stage_set_at_height": int(opened_h),
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
        "ballot_finality_policy": (
            "first_admitted_final_ballot"
            if strict_civic_governance_enabled(state)
            else "legacy_mutable_compat"
        ),
        "public_ballot_disclosure": "aggregate_only",
    }
    # Recompute after target owner/reporter metadata is present so conflict
    # filtering cannot select a party or materially connected reviewer.
    all_reviewers = eligible_reviewer_ids(state, DISPUTE_REVIEW_LANE)
    selection = select_dispute_panel(
        state,
        disputes[dispute_id],
        all_reviewers,
        round_no=1,
    )
    disputes[dispute_id]["panel_round"] = 1
    disputes[dispute_id]["panel_status"] = selection["status"]
    disputes[dispute_id]["panel_commitment"] = selection["panel_commitment"]
    disputes[dispute_id]["panel_required_size"] = selection["required_panel_size"]
    disputes[dispute_id]["substitute_required_count"] = selection["required_substitute_count"]
    disputes[dispute_id]["substitute_juror_ids"] = list(selection["substitutes"])
    disputes[dispute_id]["conflicted_juror_ids"] = list(selection["conflicted_juror_ids"])
    eligible_jurors = list(selection["panel"])
    disputes[dispute_id]["eligible_juror_ids"] = list(eligible_jurors)
    disputes[dispute_id]["assigned_jurors"] = list(eligible_jurors)
    disputes[dispute_id]["eligible_validator_count"] = int(len(eligible_jurors))
    disputes[dispute_id]["required_votes"] = int(quorum_threshold(len(eligible_jurors))) if eligible_jurors else 0
    if selection["status"] == "insufficient_reviewer_pool":
        disputes[dispute_id]["stage"] = "unassigned"
        disputes[dispute_id]["assignment_blocked_reason"] = "insufficient_constitutional_reviewer_pool"
    elif eligible_jurors:
        jurors = disputes[dispute_id].get("jurors")
        if not isinstance(jurors, dict):
            jurors = {}
        for juror in eligible_jurors:
            jurors[juror] = {
                "status": "assigned",
                "assigned_at_nonce": int(env.nonce),
                "assigned_at_height": int(opened_h),
                "panel_round": 1,
            }
        disputes[dispute_id]["jurors"] = jurors
        disputes[dispute_id]["stage"] = "juror_review"
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
    d["stage_set_at_height"] = int(_current_height(state))
    return {"applied": "DISPUTE_STAGE_SET", "dispute_id": dispute_id, "stage": stage}


def _apply_dispute_evidence_declare(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    eid = _mk_id("evidence", env, payload.get("evidence_id"))
    cid = _require_public_cid(payload.get("cid"), field="cid", tx_type=str(env.tx_type or ""))
    entry = {
        "id": eid,
        "declared_by": env.signer,
        "declared_at_nonce": int(env.nonce),
        "kind": _as_str(payload.get("kind")).strip(),
        "cid": cid,
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
    _require_dispute_reviewer_lane(state, juror, d)
    if _is_dispute_target_owner(state, d, juror):
        raise DisputeApplyError(
            "forbidden",
            "juror_conflict_target_owner",
            {
                "dispute_id": dispute_id,
                "juror": juror,
                "target_owner": _dispute_target_owner(state, d),
            },
        )
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    eligible_jurors = _dispute_eligible_juror_ids(state, d, juror)
    juror_key = _canonical_actor_key(eligible_jurors, juror, state)
    now_h = _current_height(state)
    jurors[juror_key] = {
        "status": "assigned",
        "assigned_at_nonce": int(env.nonce),
        "assigned_at_height": int(now_h),
    }
    d["jurors"] = jurors
    assigned = _normalized_str_list(list(_as_dict(d.get("jurors")).keys()))
    d["assigned_jurors"] = list(assigned)
    d["eligible_juror_ids"] = list(assigned or eligible_jurors)
    d["eligible_validator_count"] = int(len(d["eligible_juror_ids"]))
    d["required_votes"] = (
        int(quorum_threshold(len(d["eligible_juror_ids"]))) if d["eligible_juror_ids"] else 0
    )
    stage = _as_str(d.get("stage")).strip().lower()
    if stage in {"", "open"}:
        d["stage"] = "juror_review"
        d["stage_set_at_nonce"] = int(env.nonce)
        d["stage_set_at_height"] = int(now_h)
    return {"applied": "DISPUTE_JUROR_ASSIGN", "dispute_id": dispute_id, "juror": juror_key}


def _apply_dispute_juror_accept(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    _require_dispute_reviewer_lane(state, env.signer, d)
    if _is_dispute_target_owner(state, d, env.signer):
        raise DisputeApplyError(
            "forbidden",
            "juror_conflict_target_owner",
            {
                "dispute_id": dispute_id,
                "juror": env.signer,
                "target_owner": _dispute_target_owner(state, d),
            },
        )
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
            jurors[juror_key] = {
                "status": "assigned",
                "assigned_at_nonce": int(env.nonce),
                "source": "eligible_juror_ids",
            }
            d["jurors"] = jurors
            assigned = _normalized_str_list(list(jurors.keys()))
            d["assigned_jurors"] = list(assigned)
    j = _require_assigned_juror(d, env.signer)
    status = _as_str(j.get("status")).strip().lower()
    if status in {"accepted", "attended", "present"}:
        if not _as_int(j.get("accepted_at_height"), 0):
            _ensure_juror_deadlines(state, d, j, accepted_height=_current_height(state))
        jurors[juror_key] = j
        d["jurors"] = jurors
        return {
            "applied": "DISPUTE_JUROR_ACCEPT",
            "dispute_id": dispute_id,
            "status": status or "accepted",
            "idempotent": True,
            "vote_deadline_height": _as_int(j.get("vote_deadline_height"), 0),
            "safe_withdraw_until_height": _as_int(j.get("safe_withdraw_until_height"), 0),
        }
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
    _ensure_juror_deadlines(state, d, j, accepted_height=_current_height(state))
    j["attendance"] = {
        "present": True,
        "at_nonce": int(env.nonce),
        "auto": True,
        "source": "accept",
    }
    jurors[juror_key] = j
    d["jurors"] = jurors
    event = _record_dispute_juror_reputation_event(
        state,
        dispute_id=dispute_id,
        juror=juror_key,
        event_type="DISPUTE_JUROR_ACCEPTED",
        delta_milli=0,
        at_height=_current_height(state),
        at_nonce=int(env.nonce),
        reason="accepted_review_obligation",
    )
    return {
        "applied": "DISPUTE_JUROR_ACCEPT",
        "dispute_id": dispute_id,
        "present": True,
        "vote_deadline_height": _as_int(j.get("vote_deadline_height"), 0),
        "safe_withdraw_until_height": _as_int(j.get("safe_withdraw_until_height"), 0),
        "event_id": event.get("event_id"),
        "canonical_reputation_event_id": event.get("canonical_reputation_event_id"),
    }


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


def _apply_dispute_juror_withdraw(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    juror_key = _juror_key_for_actor(d, env.signer)
    j = _require_juror_status(d, env.signer, {"accepted", "attended", "present"})
    if _juror_has_vote(d, env.signer):
        raise DisputeApplyError(
            "forbidden",
            "dispute_withdraw_after_vote_forbidden",
            {"dispute_id": dispute_id, "juror": env.signer},
        )
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
        d["jurors"] = jurors
    j = jurors.get(juror_key) if isinstance(jurors.get(juror_key), dict) else j
    now_h = _current_height(state)
    if not _as_int(j.get("accepted_at_height"), 0):
        _ensure_juror_deadlines(state, d, j, accepted_height=now_h)
    safe_until = _as_int(j.get("safe_withdraw_until_height"), now_h)
    policy = _as_dict(j.get("reputation_policy")) or _dispute_reputation_params(state, d)
    safe = int(now_h) <= int(safe_until)
    delta = 0 if safe else _as_int(policy.get("late_withdraw_penalty_milli"), -500)
    event_type = "DISPUTE_JUROR_WITHDREW_EARLY" if safe else "DISPUTE_JUROR_WITHDREW_LATE"
    reason = "safe_withdraw_no_penalty" if safe else "late_withdraw_light_penalty"
    event = _record_dispute_juror_reputation_event(
        state,
        dispute_id=dispute_id,
        juror=juror_key,
        event_type=event_type,
        delta_milli=delta,
        at_height=now_h,
        at_nonce=int(env.nonce),
        reason=reason,
    )
    j["status"] = "withdrawn"
    j["withdrawn_at_nonce"] = int(env.nonce)
    j["withdrawn_at_height"] = int(now_h)
    j["withdrawal"] = {
        "safe": bool(safe),
        "event_type": event_type,
        "delta_milli": int(delta),
        "reason": _as_str(payload.get("reason") or reason),
        "event_id": event.get("event_id"),
    }
    jurors[juror_key] = j
    d["jurors"] = jurors
    return {
        "applied": "DISPUTE_JUROR_WITHDRAW",
        "dispute_id": dispute_id,
        "juror": juror_key,
        "safe": bool(safe),
        "delta_milli": int(delta),
        "event_id": event.get("event_id"),
    }


def _apply_dispute_juror_timeout(state: Json, env: TxEnvelope) -> Json:
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
        d["jurors"] = jurors
    juror_key = _juror_key_for_actor(d, juror)
    j = jurors.get(juror_key)
    if not isinstance(j, dict):
        raise DisputeApplyError(
            "forbidden", "juror_not_assigned", {"dispute_id": dispute_id, "juror": juror}
        )
    status = _as_str(j.get("status")).strip().lower()
    if status in {"timed_out"}:
        return {
            "applied": "DISPUTE_JUROR_TIMEOUT",
            "dispute_id": dispute_id,
            "juror": juror_key,
            "deduped": True,
        }
    if status not in {"accepted", "attended", "present"}:
        raise DisputeApplyError(
            "forbidden",
            "juror_wrong_status",
            {"dispute_id": dispute_id, "juror": juror, "status": status, "allowed": ["accepted"]},
        )
    if _juror_has_vote(d, juror_key):
        raise DisputeApplyError(
            "forbidden",
            "dispute_timeout_after_vote_forbidden",
            {"dispute_id": dispute_id, "juror": juror_key},
        )
    now_h = _current_height(state)
    deadline = _as_int(j.get("vote_deadline_height") or payload.get("deadline_height"), 0)
    if deadline > 0 and int(now_h) <= int(deadline):
        raise DisputeApplyError(
            "forbidden",
            "dispute_vote_deadline_not_passed",
            {
                "dispute_id": dispute_id,
                "juror": juror_key,
                "height": int(now_h),
                "deadline_height": int(deadline),
            },
        )
    policy = _as_dict(j.get("reputation_policy")) or _dispute_reputation_params(state, d)
    delta = _as_int(policy.get("timeout_penalty_milli"), -1500)
    event = _record_dispute_juror_reputation_event(
        state,
        dispute_id=dispute_id,
        juror=juror_key,
        event_type="DISPUTE_JUROR_TIMED_OUT",
        delta_milli=delta,
        at_height=now_h,
        at_nonce=int(env.nonce),
        reason="dispute_timeout_penalty",
    )
    j["status"] = "timed_out"
    j["timed_out_at_nonce"] = int(env.nonce)
    j["timed_out_at_height"] = int(now_h)
    j["timeout"] = {
        "deadline_height": int(deadline),
        "delta_milli": int(delta),
        "event_id": event.get("event_id"),
    }
    jurors[juror_key] = j
    d["jurors"] = jurors
    return {
        "applied": "DISPUTE_JUROR_TIMEOUT",
        "dispute_id": dispute_id,
        "juror": juror_key,
        "delta_milli": int(delta),
        "event_id": event.get("event_id"),
    }


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
        _ensure_juror_deadlines(state, d, j, accepted_height=_current_height(state))
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
    stage = _as_str(d.get("stage") or "").strip().lower()
    profile = _require_active_dispute_ballot_profile(
        state, dispute_id=dispute_id, stage=stage or "juror_review"
    )
    _require_dispute_reviewer_lane(state, env.signer, d)
    if _is_dispute_target_owner(state, d, env.signer):
        raise DisputeApplyError(
            "forbidden",
            "juror_conflict_target_owner",
            {
                "dispute_id": dispute_id,
                "juror": env.signer,
                "target_owner": _dispute_target_owner(state, d),
            },
        )
    _dispute_eligible_juror_ids(state, d, env.signer)
    juror_key = _juror_key_for_actor(d, env.signer)
    is_appeal_vote = stage in {"appealed", "appeal_review"}
    if bool(profile.get("strict")):
        prior_voters = _dispute_voted_juror_ids(d, appeal=is_appeal_vote)
        if any(
            set(_identity_variants(juror_key)).intersection(_identity_variants(voter))
            for voter in prior_voters
        ):
            raise DisputeApplyError(
                "conflict",
                "dispute_ballot_already_final",
                {"dispute_id": dispute_id, "juror": env.signer, "stage": stage},
            )
    else:
        prior_votes = _as_dict(d.get("appeal_panel_votes" if is_appeal_vote else "votes"))
        if any(alias in prior_votes for alias in _identity_variants(env.signer)):
            raise DisputeApplyError(
                "conflict",
                "dispute_ballot_already_final",
                {"dispute_id": dispute_id, "juror": env.signer, "stage": stage},
            )
    j = _require_juror_status(d, env.signer, {"assigned", "accepted", "present", "attended"})
    status = _as_str(j.get("status")).strip().lower()
    if status in {"", "assigned"}:
        # Voting must not implicitly accept a juror assignment. The explicit
        # accept/attendance step establishes the deterministic review window and
        # reputation obligation before a juror can mutate the vote read model.
        raise DisputeApplyError(
            "forbidden",
            "juror_not_present",
            {
                "dispute_id": dispute_id,
                "juror": env.signer,
                "status": status or "assigned",
                "requires": "DISPUTE_JUROR_ACCEPT",
            },
        )
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
        d["jurors"] = jurors
    if status == "accepted" and _as_int(j.get("vote_deadline_height"), 0) <= 0:
        _ensure_juror_deadlines(state, d, j, accepted_height=_current_height(state))
        jurors[juror_key] = j
    att = j.get("attendance")
    attendance_present = (isinstance(att, dict) and bool(att.get("present", False))) or status in {
        "present",
        "attended",
    }
    if not attendance_present:
        raise DisputeApplyError(
            "forbidden",
            "juror_not_present",
            {
                "dispute_id": dispute_id,
                "juror": env.signer,
                "status": status,
                "requires": "DISPUTE_JUROR_ACCEPT",
            },
        )
    deadline = _as_int(j.get("vote_deadline_height"), 0)
    if deadline > 0 and _current_height(state) > deadline:
        raise DisputeApplyError(
            "forbidden",
            "dispute_vote_deadline_passed",
            {
                "dispute_id": dispute_id,
                "juror": env.signer,
                "height": _current_height(state),
                "deadline_height": int(deadline),
            },
        )
    votes_key = "appeal_panel_votes" if is_appeal_vote else "votes"
    votes = d.get(votes_key)
    if not isinstance(votes, dict):
        votes = {}
    strict_ballot = bool(profile.get("strict"))
    panel_round = int(d.get("appeal_panel_round") or d.get("panel_round") or 1)
    ballot_nullifier = _dispute_ballot_nullifier(
        dispute_id=dispute_id,
        panel_round=panel_round,
        juror=juror_key,
        appeal=is_appeal_vote,
    )
    nullifiers = _dispute_ballot_nullifiers(d, appeal=is_appeal_vote)
    voted_jurors = _dispute_voted_juror_ids(d, appeal=is_appeal_vote)

    if strict_ballot:
        # Migrate any attributable local/dev ballot state once, then erase it.
        if votes:
            counts = _aggregate_dispute_counts(d, appeal=is_appeal_vote)
            for legacy_juror, record in sorted(votes.items(), key=lambda item: str(item[0])):
                if not isinstance(record, dict):
                    continue
                choice = _as_str(
                    record.get("decision") if is_appeal_vote else record.get("vote") or record.get("choice")
                ).strip().lower()
                if choice:
                    counts[choice] = int(counts.get(choice, 0)) + 1
                canonical_legacy = _as_str(legacy_juror).strip()
                if canonical_legacy:
                    voted_jurors.append(canonical_legacy)
                    legacy_nullifier = _dispute_ballot_nullifier(
                        dispute_id=dispute_id,
                        panel_round=panel_round,
                        juror=canonical_legacy,
                        appeal=is_appeal_vote,
                    )
                    nullifiers.setdefault(
                        legacy_nullifier,
                        {"height": int(_as_int(record.get("height"), 0)), "migrated_from_attributable_state": True},
                    )
                legacy_resolution = record.get("resolution") if isinstance(record.get("resolution"), dict) else None
                _record_deattributed_resolution_option(
                    d,
                    choice=choice,
                    resolution=legacy_resolution,
                    summary=_as_str(record.get("summary")),
                    appeal=is_appeal_vote,
                )
            voted_jurors[:] = sorted(set(voted_jurors))
            votes.clear()
            d[votes_key] = {}
        if ballot_nullifier in nullifiers or juror_key in set(voted_jurors):
            raise DisputeApplyError(
                "conflict",
                "dispute_ballot_already_final",
                {"dispute_id": dispute_id, "juror": env.signer, "stage": stage},
            )
    else:
        for alias in _identity_variants(env.signer):
            if alias in votes:
                raise DisputeApplyError(
                    "conflict",
                    "dispute_ballot_already_final",
                    {"dispute_id": dispute_id, "juror": env.signer, "stage": stage},
                )

    resolution = payload.get("resolution") if isinstance(payload.get("resolution"), dict) else None
    vote_choice = _as_str(payload.get("vote")).strip().lower()
    if not is_appeal_vote and vote_choice not in {"yes", "no", "abstain"}:
        raise DisputeApplyError(
            "invalid_payload",
            "invalid_dispute_vote_choice",
            {"dispute_id": dispute_id, "vote": vote_choice, "allowed": ["abstain", "no", "yes"]},
        )

    if strict_ballot:
        if not is_appeal_vote:
            counts = _aggregate_dispute_counts(d)
            counts[vote_choice] = int(counts.get(vote_choice, 0)) + 1
            _record_deattributed_resolution_option(
                d,
                choice=vote_choice,
                resolution=resolution,
            )
        voted_jurors.append(juror_key)
        voted_jurors[:] = sorted(set(voted_jurors))
        nullifiers[ballot_nullifier] = {
            "height": int(_current_height(state)),
            "panel_round": panel_round,
            "ballot_profile_id": _as_str(profile.get("profile_id")),
            "final": True,
        }
        d[votes_key] = {}
    elif not is_appeal_vote:
        vote_entry: Json = {
            "vote": vote_choice,
            "at_nonce": int(env.nonce),
            "height": int(_current_height(state)),
            "ballot_profile_id": _as_str(profile.get("profile_id")),
            "final": True,
        }
        if isinstance(resolution, dict) and resolution:
            vote_entry["resolution"] = dict(resolution)
        for alias in _identity_variants(env.signer):
            if alias != juror_key:
                votes.pop(alias, None)
        votes[juror_key] = vote_entry
        d["votes"] = votes
    now_h = _current_height(state)
    vote_event = _record_dispute_juror_reputation_event(
        state,
        dispute_id=dispute_id,
        juror=juror_key,
        event_type="DISPUTE_JUROR_VOTED_ON_TIME",
        delta_milli=250,
        at_height=now_h,
        at_nonce=int(env.nonce),
        reason="voted_before_deadline",
    )
    j["status"] = "completed"
    j["completed_at_nonce"] = int(env.nonce)
    j["completed_at_height"] = int(now_h)
    j["completion"] = {"event_id": vote_event.get("event_id"), "delta_milli": 250}
    jurors = d.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}
    jurors[juror_key] = j
    d["jurors"] = jurors

    appeal_panel_result = _maybe_record_appeal_panel_vote(state, d, env, payload, juror_key)
    voter_commitment = _canonical_hash(
        {
            "domain": "weall.dispute.ballot-admission.v1",
            "dispute_id": dispute_id,
            "panel_round": int(d.get("appeal_panel_round") or d.get("panel_round") or 1),
            "juror": juror_key,
        }
    )
    _dispute_ballot_receipts(state).append(
        {
            "dispute_id": dispute_id,
            "panel_round": int(d.get("appeal_panel_round") or d.get("panel_round") or 1),
            "stage": stage,
            "voter_commitment": voter_commitment,
            "ballot_profile_id": _as_str(profile.get("profile_id")),
            "height": int(now_h),
            "final": True,
        }
    )

    parent_ref = (
        env.parent
        or _as_str(payload.get("_parent_ref")).strip()
        or f"tx:{env.signer}:{int(env.nonce)}"
    )
    _maybe_schedule_dispute_auto_resolution(
        state,
        d,
        dispute_id,
        current_height=int(state.get("height", 0) or 0),
        parent_ref=parent_ref,
    )

    out: Json = {
        "applied": "DISPUTE_VOTE_SUBMIT",
        "dispute_id": dispute_id,
        "event_id": vote_event.get("event_id"),
        "canonical_reputation_event_id": vote_event.get("canonical_reputation_event_id"),
    }
    if appeal_panel_result is not None:
        out["appeal_panel_result"] = appeal_panel_result
    return out


def _maybe_record_appeal_panel_vote(
    state: Json, d: Json, env: TxEnvelope, payload: Json, juror_key: str
) -> Json | None:
    """Record an appeal decision without publishing juror-to-choice mappings."""

    stage = _as_str(d.get("stage") or "").strip().lower()
    appeal_resolution = (
        payload.get("appeal_resolution")
        if isinstance(payload.get("appeal_resolution"), dict)
        else None
    )
    raw_decision = (
        _as_str(
            payload.get("appeal_decision")
            or payload.get("appeal_vote")
            or (appeal_resolution or {}).get("decision")
            or (appeal_resolution or {}).get("outcome")
            or ""
        )
        .strip()
        .lower()
    )
    if stage not in {"appealed", "appeal_review"} and not raw_decision:
        return None
    if raw_decision not in {"uphold", "reverse", "modify"}:
        raise DisputeApplyError(
            "invalid_payload",
            "invalid_appeal_vote_choice",
            {
                "dispute_id": _as_str(d.get("id")),
                "decision": raw_decision,
                "allowed": ["modify", "reverse", "uphold"],
            },
        )

    strict_ballot = strict_civic_governance_enabled(state)
    summary = _as_str(
        payload.get("summary") or (appeal_resolution or {}).get("summary") or ""
    ).strip()

    if strict_ballot:
        counts = _aggregate_dispute_counts(d, appeal=True)
        counts[raw_decision] = int(counts.get(raw_decision, 0)) + 1
        _record_deattributed_resolution_option(
            d,
            choice=raw_decision,
            resolution=appeal_resolution,
            summary=summary,
            appeal=True,
        )
        d["appeal_panel_votes"] = {}
        total_votes = int(sum(counts.values()))
    else:
        panel_votes = d.get("appeal_panel_votes")
        if not isinstance(panel_votes, dict):
            panel_votes = {}
        for alias in _identity_variants(env.signer):
            if alias in panel_votes:
                raise DisputeApplyError(
                    "conflict",
                    "dispute_ballot_already_final",
                    {
                        "dispute_id": _as_str(d.get("id")),
                        "juror": env.signer,
                        "stage": stage,
                    },
                )
        vote_entry: Json = {
            "decision": raw_decision,
            "at_nonce": int(env.nonce),
            "height": int(state.get("height", 0) or 0),
        }
        if isinstance(appeal_resolution, dict):
            vote_entry["resolution"] = dict(appeal_resolution)
        if summary:
            vote_entry["summary"] = summary
        panel_votes[juror_key] = vote_entry
        d["appeal_panel_votes"] = panel_votes
        counts = {"uphold": 0, "reverse": 0, "modify": 0}
        for vote in panel_votes.values():
            if isinstance(vote, dict):
                decision = _as_str(vote.get("decision") or "").strip().lower()
                if decision in counts:
                    counts[decision] += 1
        total_votes = len(panel_votes)

    d["stage"] = "appeal_review"
    eligible = _dispute_eligible_juror_ids(state, d, str(env.signer))
    required = int(d.get("required_votes") or 0)
    if required <= 0:
        required = int(quorum_threshold(len(eligible))) if eligible else 1

    decision = ""
    for candidate in ("reverse", "modify", "uphold"):
        if int(counts.get(candidate, 0)) >= required:
            decision = candidate
            break
    result: Json = {
        "votes": int(total_votes),
        "required_votes": int(required),
        "counts": {
            "uphold": int(counts.get("uphold", 0)),
            "reverse": int(counts.get("reverse", 0)),
            "modify": int(counts.get("modify", 0)),
        },
        "reached": bool(decision),
    }
    if decision:
        resolution: Json = {"decision": decision}
        if strict_ballot:
            selected = _select_deattributed_resolution(
                d, winning_choice=decision, appeal=True
            )
            resolution.update(selected)
            resolution["decision"] = decision
        else:
            panel_votes = _as_dict(d.get("appeal_panel_votes"))
            for key in sorted(panel_votes):
                vote = panel_votes.get(key)
                if (
                    not isinstance(vote, dict)
                    or _as_str(vote.get("decision") or "").strip().lower() != decision
                ):
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
    return result


def _apply_dispute_resolve(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    d["resolved"] = True
    d["resolved_at_nonce"] = int(env.nonce)

    # Constitutional-clock testnet mode makes dispute finality appealable.
    # The resolution/verdict is recorded now, but final receipt/enforcement is
    # delayed until the deterministic appeal window closes or the appeal path
    # is resolved. Legacy/dev flows keep the historical immediate final receipt.
    constitutional_appeal_mode = _constitutional_clock_enabled(state)
    raw_resolution = payload.get("resolution")
    resolution_for_state = (
        _quarantine_content_enforcement_for_appeal_window(raw_resolution)
        if constitutional_appeal_mode
        else raw_resolution
    )
    d["resolution"] = resolution_for_state
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
    res = d.get("resolution")
    applied_actions: list[Json] = []
    queued_actions: list[Json] = []
    if isinstance(res, dict):
        actions = res.get("actions")
        if isinstance(actions, list) and not constitutional_appeal_mode:
            valid_actions = _validate_dispute_enforcement_actions(
                state,
                actions=[a for a in actions if isinstance(a, dict)],
                dispute_id=dispute_id,
                parent_ref=parent_ref,
            )
            applied_actions = _apply_inline_content_enforcement(
                state,
                actions=valid_actions,
                current_height=int(base_due_h),
                parent_ref=parent_ref,
            )
            applied_keys = {
                (
                    _as_str(a.get("tx_type")).strip(),
                    _as_str(
                        (a.get("payload") if isinstance(a.get("payload"), dict) else {}).get(
                            "target_id"
                        )
                        or (a.get("payload") if isinstance(a.get("payload"), dict) else {}).get(
                            "id"
                        )
                    ).strip(),
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

    return {
        "applied": "DISPUTE_RESOLVE",
        "dispute_id": dispute_id,
        "enforcement_applied": applied_actions,
        "enforcement_queued": queued_actions,
    }


def _apply_dispute_appeal(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    dispute_id = _as_str(payload.get("dispute_id")).strip()
    if not dispute_id:
        raise DisputeApplyError("invalid_payload", "missing_dispute_id", {"tx_type": env.tx_type})
    d = _get_dispute(state, dispute_id)
    stage = _as_str(d.get("stage")).strip().lower()
    if _constitutional_clock_enabled(state):
        if stage not in {"appeal_window", "appealed", "appeal_review"}:
            raise DisputeApplyError(
                "forbidden", "appeal_window_not_open", {"dispute_id": dispute_id, "stage": stage}
            )
        deadline = int(d.get("appeal_deadline_height") or 0)
        current_h = int(state.get("height", 0) or 0)
        if deadline > 0 and current_h > deadline:
            raise DisputeApplyError(
                "forbidden",
                "appeal_window_closed",
                {"dispute_id": dispute_id, "deadline_height": deadline, "height": current_h},
            )
    _require_dispute_appeal_actor(state, d, _as_str(env.signer).strip())
    appeals = d.get("appeals")
    if not isinstance(appeals, list):
        appeals = []
    for existing in appeals:
        if isinstance(existing, dict) and set(_identity_variants(existing.get("by"))).intersection(
            _identity_variants(env.signer)
        ):
            raise DisputeApplyError(
                "conflict",
                "appeal_already_filed",
                {"dispute_id": dispute_id, "appellant": env.signer},
            )

    appeals.append(
        {
            "by": env.signer,
            "at_nonce": int(env.nonce),
            "height": int(state.get("height", 0) or 0),
            "payload": payload,
        }
    )
    d["appeals"] = appeals

    original_panel = _normalized_str_list(d.get("assigned_jurors"))
    original_substitutes = _normalized_str_list(d.get("substitute_juror_ids"))
    appeal_round = int(d.get("appeal_panel_round") or 1)
    candidates = eligible_reviewer_ids(state, DISPUTE_REVIEW_LANE)
    selection = select_dispute_panel(
        state,
        d,
        candidates,
        round_no=appeal_round + 1,
        exclude_ids=original_panel + original_substitutes,
    )
    appeal_panel = list(selection["panel"])
    if bool(selection.get("strict")) and selection.get("status") != "assigned":
        raise DisputeApplyError(
            "forbidden",
            "insufficient_fresh_appeal_panel",
            {
                "dispute_id": dispute_id,
                "required_panel_size": selection.get("required_panel_size"),
                "required_substitute_count": selection.get("required_substitute_count"),
                "available_candidate_count": selection.get("available_candidate_count"),
            },
        )

    now_h = int(state.get("height", 0) or 0)
    d["original_panel_juror_ids"] = list(original_panel)
    d["original_substitute_juror_ids"] = list(original_substitutes)
    d["appeal_panel_round"] = int(appeal_round + 1)
    d["appeal_panel_status"] = selection["status"]
    d["appeal_panel_commitment"] = selection["panel_commitment"]
    d["appeal_panel_juror_ids"] = list(appeal_panel)
    d["appeal_substitute_juror_ids"] = list(selection["substitutes"])
    d["appeal_conflicted_juror_ids"] = list(selection["conflicted_juror_ids"])
    d["eligible_juror_ids"] = list(appeal_panel)
    d["eligible_validator_count"] = int(len(appeal_panel))
    d["required_votes"] = int(quorum_threshold(len(appeal_panel))) if appeal_panel else 0
    d["appeal_panel_votes"] = {}
    d["appeal_vote_counts"] = {}
    d["appeal_ballot_nullifiers"] = {}
    d["appeal_voted_juror_ids"] = []
    d["appeal_resolution_options"] = {}
    d["jurors"] = {
        juror: {
            "status": "assigned",
            "assigned_at_nonce": int(env.nonce),
            "assigned_at_height": now_h,
            "panel_round": int(appeal_round + 1),
            "panel_kind": "appeal",
        }
        for juror in appeal_panel
    }
    d["assigned_jurors"] = list(appeal_panel)
    d["stage"] = "appeal_review" if appeal_panel else "appealed"
    d["stage_set_at_height"] = now_h
    return {
        "applied": "DISPUTE_APPEAL",
        "dispute_id": dispute_id,
        "appeal_panel_status": selection["status"],
        "appeal_panel_commitment": selection["panel_commitment"],
    }


def _record_dispute_juror_accountability(state: Json, dispute: Json, *, dispute_id: str) -> Json:
    assigned = _normalized_str_list(dispute.get("assigned_jurors"))
    votes = _as_dict(dispute.get("votes"))
    voted: set[str] = set()
    for voter in _normalized_str_list(dispute.get("voted_juror_ids")):
        for variant in _identity_variants(voter):
            voted.add(variant)
    for voter in votes.keys():
        for variant in _identity_variants(voter):
            voted.add(variant)
    root = state.get("dispute_juror_accountability")
    if not isinstance(root, dict):
        root = {"by_juror": {}, "events": []}
        state["dispute_juror_accountability"] = root
    by_juror = root.get("by_juror")
    if not isinstance(by_juror, dict):
        by_juror = {}
        root["by_juror"] = by_juror
    events = root.get("events")
    if not isinstance(events, list):
        events = []
        root["events"] = events
    recorded: list[str] = []
    accounts = _as_dict(state.get("accounts"))
    juror_records = _as_dict(dispute.get("jurors"))
    for juror in assigned:
        jrec = _as_dict(juror_records.get(juror))
        if _as_str(jrec.get("status")).strip().lower() in {"declined", "withdrawn", "timed_out"}:
            continue
        if any(variant in voted for variant in _identity_variants(juror)):
            continue
        rec = by_juror.get(juror)
        if not isinstance(rec, dict):
            rec = {"juror_id": juror, "missed_vote_count": 0, "events": []}
        event = {
            "event": "assigned_dispute_vote_missed",
            "dispute_id": dispute_id,
            "height": int(state.get("height") or 0),
        }
        rec["missed_vote_count"] = int(rec.get("missed_vote_count") or 0) + 1
        rec["eligible_for_dispute_jury"] = False
        rec["status"] = "juror_accountability_flagged"
        rec.setdefault("events", []).append(event)
        by_juror[juror] = rec
        acct = accounts.get(juror)
        if isinstance(acct, dict):
            acct["dispute_juror_eligible"] = False
            acct["dispute_juror_suspended_reason"] = "assigned_dispute_vote_missed"
            acct["dispute_juror_suspended_at_height"] = int(state.get("height") or 0)
        events.append({"juror_id": juror, **event})
        recorded.append(juror)
    return {"applied": bool(recorded), "jurors": recorded}


def _final_receipt_resolution(dispute: Json, payload: Json) -> tuple[Json, Json]:
    """Return the effective final resolution and appeal metadata.

    Constitutional-clock disputes delay enforcement until final receipt.  If an
    appeal was submitted, a system final receipt may carry an ``appeal_resolution``
    object with a deterministic decision.  ``reverse`` suppresses original
    enforcement actions; ``modify`` uses the appeal-provided actions; ``uphold``
    keeps the original resolution unless replacement actions are supplied.
    """

    original = (
        payload.get("resolution")
        if isinstance(payload.get("resolution"), dict)
        else dispute.get("resolution")
    )
    resolution: Json = dict(original) if isinstance(original, dict) else {}
    appeal_resolution = payload.get("appeal_resolution")
    if not isinstance(appeal_resolution, dict):
        appeal_resolution = {}
    if not appeal_resolution:
        panel_result = dispute.get("appeal_panel_result")
        if (
            isinstance(panel_result, dict)
            and bool(panel_result.get("reached"))
            and isinstance(panel_result.get("resolution"), dict)
        ):
            appeal_resolution = dict(panel_result["resolution"])
            appeal_resolution.setdefault("source", "appeal_panel")

    appeals = dispute.get("appeals") if isinstance(dispute.get("appeals"), list) else []
    appeal_meta: Json = {
        "appealed": bool(appeals),
        "appeal_count": len(appeals),
        "decision": "none",
    }
    if appeal_resolution:
        decision = (
            _as_str(
                appeal_resolution.get("decision") or appeal_resolution.get("outcome") or "uphold"
            )
            .strip()
            .lower()
        )
        if decision not in {"uphold", "reverse", "modify"}:
            decision = "uphold"
        appeal_meta["decision"] = decision
        appeal_meta["resolution"] = dict(appeal_resolution)
        if decision == "reverse":
            resolution["appeal_decision"] = "reverse"
            resolution["actions"] = []
            resolution["summary"] = _as_str(
                appeal_resolution.get("summary") or "Appeal reversed the dispute outcome."
            )
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
    existing = root.get(rid)
    if isinstance(existing, dict):
        return {
            "applied": "DISPUTE_FINAL_RECEIPT",
            "receipt_id": rid,
            "receipt": True,
            "deduped": True,
            "appeal_finalization": dict(existing.get("appeal_finalization") or {}),
            "enforcement_applied": list(existing.get("enforcement_applied") or []),
        }
    applied_actions: list[Json] = []
    appeal_meta: Json = {"appealed": False, "decision": "none", "appeal_count": 0}
    final_resolution: Json = (
        payload.get("resolution") if isinstance(payload.get("resolution"), dict) else {}
    )

    if dispute_id:
        d = _get_dispute(state, dispute_id)
        final_resolution, appeal_meta = _final_receipt_resolution(d, payload)
        d["final_resolution"] = dict(final_resolution)
        d["appeal_finalization"] = dict(appeal_meta)
        d["juror_accountability"] = _record_dispute_juror_accountability(
            state, d, dispute_id=dispute_id
        )
        # If an appeal exists but no appeal decision has been supplied, do not
        # silently finalize enforcement.  Keep the case in appeal review and
        # record an audit receipt for the attempted finalization.
        if appeal_meta.get("decision") == "pending_review":
            d["stage"] = "appeal_review"
        else:
            parent_ref = _as_str(
                payload.get("_parent_ref") or env.parent or f"tx:{env.signer}:{int(env.nonce)}"
            ).strip()
            actions = (
                final_resolution.get("actions")
                if isinstance(final_resolution.get("actions"), list)
                else []
            )
            valid_actions = _validate_dispute_enforcement_actions(
                state,
                actions=[a for a in actions if isinstance(a, dict)],
                dispute_id=dispute_id,
                parent_ref=parent_ref,
            )
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
    "DISPUTE_JUROR_WITHDRAW",
    "DISPUTE_JUROR_TIMEOUT",
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
    if t == "DISPUTE_JUROR_WITHDRAW":
        return _apply_dispute_juror_withdraw(state, env)
    if t == "DISPUTE_JUROR_TIMEOUT":
        return _apply_dispute_juror_timeout(state, env)
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
