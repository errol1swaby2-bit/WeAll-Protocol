from __future__ import annotations

"""Deterministic phase/quorum read models for governance and disputes.

The helpers in this module are intentionally read-model oriented and deterministic.
They do not read wall-clock time, peer/session online status, or frontend-local
state.  Phase quorum is based on the saved phase-open eligible snapshot.  A new
snapshot may be written only by explicit phase-opening apply paths.
"""

import hashlib
import json
from typing import Any

from weall.runtime.bft_hotstuff import quorum_threshold

Json = dict[str, Any]

SMALL_NETWORK_MIN_ELIGIBLE = 4
SMALL_NETWORK_MIN_PARTICIPATION = 2


def _d(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _s(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value).strip()
    except Exception:
        return ""


def _i(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _identity_variants(value: Any) -> list[str]:
    raw = _s(value)
    if not raw:
        return []
    base = raw[1:] if raw.startswith("@") else raw
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (raw, base, f"@{base}" if base else ""):
        c = _s(candidate)
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _canonical_id(value: Any) -> str:
    variants = _identity_variants(value)
    if not variants:
        return ""
    # Prefer the @ form for readable API/documentation status, but preserve a
    # bare-only identity if no @-form can be derived.
    for item in variants:
        if item.startswith("@"):
            return item
    return variants[0]


def normalize_identity_list(items: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in _l(items):
        ident = _canonical_id(item)
        if not ident or ident in seen:
            continue
        seen.add(ident)
        out.append(ident)
    return sorted(out)


def canonical_list_root(items: Any) -> str:
    normalized = normalize_identity_list(items)
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def current_height(state: Json) -> int:
    return _i(state.get("height"), 0)


def _quorum_bps_from_state(state: Json, *, flow_type: str) -> int:
    params = _d(state.get("params"))
    root = _d(params.get("phase_progression"))
    flow = _d(root.get(flow_type))
    raw = flow.get("quorum_bps")
    if raw is None:
        raw = _d(params.get(flow_type)).get("quorum_bps")
    if raw is None and flow_type == "governance":
        raw = _d(_d(state.get("gov_config")).get("quorum")).get("quorum_bps")
    bps = _i(raw, 0)
    return bps if 1 <= bps <= 10000 else 0


def quorum_required_for_count(state: Json, *, flow_type: str, eligible_count: int) -> int:
    count = max(0, int(eligible_count))
    if count <= 0:
        return 0
    bps = _quorum_bps_from_state(state, flow_type=flow_type)
    if bps > 0:
        required = (count * bps + 9999) // 10000
        return max(1, min(count, int(required)))
    # Preserve the existing HotStuff-style default where the repository already
    # used quorum_threshold(count), while surfacing it as an explicit policy.
    return int(quorum_threshold(count))


def _vote_map_for_governance(proposal: Json, phase: str) -> Json:
    if phase == "poll":
        return _d(proposal.get("poll_votes"))
    return _d(proposal.get("votes"))


def _vote_map_for_dispute(dispute: Json, phase: str) -> Json:
    if phase in {"appealed", "appeal_review"}:
        panel = _d(dispute.get("appeal_panel_votes"))
        if panel:
            return panel
    return _d(dispute.get("votes"))


def participation_count_for_snapshot(votes: Any, eligible_snapshot: Any) -> int:
    vote_map = _d(votes)
    eligible = normalize_identity_list(eligible_snapshot)
    count = 0
    for eligible_id in eligible:
        variants = set(_identity_variants(eligible_id))
        for voter in vote_map.keys():
            if variants.intersection(_identity_variants(voter)):
                count += 1
                break
    return int(count)


def _deadline_for_phase(obj: Json, phase: str, *, default_open_height: int) -> int:
    # Explicit deadline fields take priority.  Different flows historically used
    # a mixture of per-phase and generic names; normalize without mutating.
    explicit_keys = [
        f"{phase}_deadline_height",
        f"{phase}_end_height",
        "deadline_height",
        "ends_at_height",
        "end_height",
        "vote_deadline_height",
        "review_deadline_height",
    ]
    for key in explicit_keys:
        val = _i(obj.get(key), 0)
        if val > 0:
            return int(val)
    rules = _d(obj.get("rules"))
    window_keys = [f"{phase}_window_blocks", "vote_window_blocks", "review_window_blocks", "phase_window_blocks"]
    for key in window_keys:
        window = _i(rules.get(key), 0)
        if window > 0:
            return int(default_open_height) + int(window)
    return 0


def _next_governance_phase(phase: str) -> str:
    return {
        "draft": "poll",
        "poll": "revision",
        "revision": "validation",
        "validation": "voting",
        "vote": "closed",
        "voting": "closed",
        "closed": "tallied",
        "tallied": "finalized",
        "executed": "finalized",
    }.get(phase, "")


def _next_dispute_phase(phase: str) -> str:
    return {
        "open": "juror_review",
        "juror_review": "resolved",
        "voting": "resolved",
        "appeal_window": "appeal_review",
        "appealed": "appeal_review",
        "appeal_review": "finalized",
    }.get(phase, "")


def _transition_reason(*, quorum_reached: bool, deadline_reached: bool) -> str:
    if quorum_reached and deadline_reached:
        return "block_height_and_quorum"
    if quorum_reached:
        return "quorum"
    if deadline_reached:
        return "block_height"
    return "none"


def _small_network_blockers(state: Json, *, eligible_count: int, quorum_required: int) -> list[str]:
    params = _d(state.get("params"))
    phase_params = _d(params.get("phase_progression"))
    min_eligible = _i(phase_params.get("minimum_quorum_route_eligible_count"), SMALL_NETWORK_MIN_ELIGIBLE)
    min_participation = _i(phase_params.get("minimum_quorum_route_participation_count"), SMALL_NETWORK_MIN_PARTICIPATION)
    blockers: list[str] = []
    if eligible_count > 0 and eligible_count < min_eligible:
        blockers.append("small_network_quorum_route_not_public_beta_evidence")
    if quorum_required > 0 and quorum_required < min_participation:
        blockers.append("quorum_required_below_public_legitimacy_floor")
    return blockers


def governance_phase_status(state: Json, proposal: Json, proposal_id: str | None = None) -> Json:
    phase = _s(proposal.get("stage") or proposal.get("status") or "draft").lower() or "draft"
    pid = _s(proposal_id or proposal.get("proposal_id") or proposal.get("id"))
    open_height = _i(
        proposal.get(f"{phase}_opened_at_height")
        or proposal.get(f"{phase}_at_height")
        or proposal.get("phase_open_height")
        or proposal.get("stage_set_at_height")
        or proposal.get("created_at_height"),
        0,
    )
    eligible = normalize_identity_list(proposal.get("eligible_validator_ids"))
    eligible_count = len(eligible) if eligible else _i(proposal.get("eligible_validator_count"), 0)
    required = _i(proposal.get("required_votes"), 0)
    if required <= 0 and eligible_count > 0:
        required = quorum_required_for_count(state, flow_type="governance", eligible_count=eligible_count)
    votes = _vote_map_for_governance(proposal, phase)
    participation = participation_count_for_snapshot(votes, eligible) if eligible else len(votes)
    deadline = _deadline_for_phase(proposal, phase, default_open_height=open_height)
    h = current_height(state)
    deadline_reached = bool(deadline > 0 and h >= deadline)
    quorum_reached = bool(required > 0 and participation >= required)
    reason = _transition_reason(quorum_reached=quorum_reached, deadline_reached=deadline_reached)
    blockers = _small_network_blockers(state, eligible_count=eligible_count, quorum_required=required)
    if required <= 0:
        blockers.append("quorum_denominator_empty")
    if phase in {"finalized", "withdrawn"}:
        next_step = "phase complete"
    elif reason == "none":
        next_step = "Waiting for more eligible votes or block-height deadline"
    else:
        next_step = "Finalization available" if phase in {"vote", "voting", "closed", "tallied"} else f"Next phase: {_next_governance_phase(phase) or 'review'}"
    return {
        "ok": True,
        "flow_type": "governance",
        "object_id": pid,
        "proposal_id": pid,
        "phase": phase,
        "phase_open_height": int(open_height),
        "deadline_height": int(deadline),
        "blocks_remaining": max(0, int(deadline) - int(h)) if deadline > 0 else None,
        "eligible_snapshot_height": int(open_height),
        "eligible_snapshot_root": canonical_list_root(eligible),
        "eligible_count": int(eligible_count),
        "quorum_policy_id": "phase_snapshot_hotstuff_threshold_or_configured_bps",
        "quorum_bps": _quorum_bps_from_state(state, flow_type="governance") or None,
        "quorum_required": int(required),
        "participation_count": int(participation),
        "quorum_reached": bool(quorum_reached),
        "deadline_reached": bool(deadline_reached),
        "transition_allowed": bool(reason != "none"),
        "transition_reason": reason,
        "next_phase": _next_governance_phase(phase),
        "next_step": next_step,
        "blocking_reasons": sorted(set(blockers)),
        "denominator_policy": "phase_open_snapshot_fixed_until_next_phase",
        "online_user_quorum_forbidden": True,
        "truth_boundary": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
    }


def dispute_phase_status(state: Json, dispute: Json, dispute_id: str | None = None) -> Json:
    phase = _s(dispute.get("stage") or "open").lower() or "open"
    did = _s(dispute_id or dispute.get("id") or dispute.get("dispute_id"))
    open_height = _i(dispute.get("stage_set_at_height") or dispute.get("opened_at_height"), 0)
    eligible = normalize_identity_list(dispute.get("eligible_juror_ids") or dispute.get("assigned_jurors"))
    eligible_count = len(eligible) if eligible else _i(dispute.get("eligible_validator_count"), 0)
    required = _i(dispute.get("required_votes"), 0)
    if required <= 0 and eligible_count > 0:
        required = quorum_required_for_count(state, flow_type="dispute", eligible_count=eligible_count)
    votes = _vote_map_for_dispute(dispute, phase)
    participation = participation_count_for_snapshot(votes, eligible) if eligible else len(votes)
    deadline = _deadline_for_phase(dispute, phase, default_open_height=open_height)
    h = current_height(state)
    deadline_reached = bool(deadline > 0 and h >= deadline)
    quorum_reached = bool(required > 0 and participation >= required)
    reason = _transition_reason(quorum_reached=quorum_reached, deadline_reached=deadline_reached)
    blockers = _small_network_blockers(state, eligible_count=eligible_count, quorum_required=required)
    if required <= 0:
        blockers.append("quorum_denominator_empty")
    if bool(dispute.get("resolved")) or phase in {"resolved", "finalized"}:
        next_step = "phase complete"
    elif reason == "none":
        next_step = "Waiting for more eligible votes or block-height deadline"
    else:
        next_step = f"Next phase: {_next_dispute_phase(phase) or 'resolution review'}"
    return {
        "ok": True,
        "flow_type": "dispute",
        "object_id": did,
        "dispute_id": did,
        "phase": phase,
        "phase_open_height": int(open_height),
        "deadline_height": int(deadline),
        "blocks_remaining": max(0, int(deadline) - int(h)) if deadline > 0 else None,
        "eligible_snapshot_height": int(open_height),
        "eligible_snapshot_root": canonical_list_root(eligible),
        "eligible_count": int(eligible_count),
        "quorum_policy_id": "phase_snapshot_dispute_reviewer_threshold",
        "quorum_bps": _quorum_bps_from_state(state, flow_type="dispute") or None,
        "quorum_required": int(required),
        "participation_count": int(participation),
        "quorum_reached": bool(quorum_reached),
        "deadline_reached": bool(deadline_reached),
        "transition_allowed": bool(reason != "none"),
        "transition_reason": reason,
        "next_phase": _next_dispute_phase(phase),
        "next_step": next_step,
        "blocking_reasons": sorted(set(blockers)),
        "denominator_policy": "phase_open_snapshot_fixed_until_next_phase",
        "online_user_quorum_forbidden": True,
        "truth_boundary": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
    }
