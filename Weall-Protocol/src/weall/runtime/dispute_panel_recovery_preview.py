from __future__ import annotations

"""Read-only analysis of post-assignment dispute panel conflicts.

This module is deliberately NOT wired to the block scheduler, transaction
dispatcher, or governance execution. It cannot recuse, appoint, reduce a
constitutional panel/quorum, waive reputation penalties, or authorize a ballot.
It reports proposed substitutions from the *committed original reserve order*
and explicit reasons a future versioned consensus design needs review.
"""

import math
from typing import Any

from weall.runtime.apply.dispute import (
    _dispute_conflict_account_ids,
    _dispute_panel_size,
    _identity_variants,
    _resolve_account_identity,
)
from weall.runtime.ballot_policy import strict_civic_governance_enabled
from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.reviewer_responsibilities import (
    DISPUTE_REVIEW_LANE,
    reviewer_lane_active,
)
from weall.runtime.severe_sanction_boundary import is_explicit_severe_account_sanction

Json = dict[str, Any]


def _identities(state: Json, raw: Any) -> tuple[list[str], bool]:
    """Preserve committed order; refuse duplicated/ambiguous aliases."""
    if not isinstance(raw, list):
        return [], False
    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            return [], False
        resolved = _resolve_account_identity(state, item)
        variants = _identity_variants(resolved)
        key = variants[1] if len(variants) > 1 else resolved
        if not key or key in seen or resolved.upper() == "SYSTEM":
            return [], False
        seen.add(key)
        result.append(resolved)
    return result, True


def _same_identity(a: str, b: str) -> bool:
    return bool(set(_identity_variants(a)).intersection(_identity_variants(b)))


def _has_existing_ballots(dispute: Json) -> bool:
    for name in ("voted_juror_ids", "votes", "ballot_nullifiers"):
        value = dispute.get(name)
        if isinstance(value, (list, dict)) and value:
            return True
    counts = dispute.get("vote_counts")
    if isinstance(counts, dict):
        for value in counts.values():
            if type(value) is int and value > 0:
                return True
    return False


def preview_dispute_panel_recovery(state: Json, dispute_id: str) -> Json:
    """Describe candidate replacements without changing either input object.

    No proposal here proves the original panel commitment's witness lineage.
    A candidate is not a canonically executable replacement or new panel round.
    Replenishment, appeal rights, deadlines and reputation fairness are
    deliberately left for separately authorized constitutional review.
    """

    disputes = state.get("disputes_by_id")
    dispute = disputes.get(dispute_id) if isinstance(disputes, dict) else None
    if not isinstance(dispute, dict):
        return {"status": "missing_dispute", "dispute_id": dispute_id, "authorized": False}

    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    version = params.get("dispute_material_conflict_gate_version", 1)
    strict = strict_civic_governance_enabled(state)
    panel, panel_well_formed = _identities(state, dispute.get("assigned_jurors"))
    reserves, reserve_well_formed = _identities(state, dispute.get("substitute_juror_ids"))
    required = _dispute_panel_size(dispute)
    needed_reserves = math.ceil(required * 0.20)
    conflicts = _dispute_conflict_account_ids(state, dispute)
    conflict_ids = [
        juror for juror in panel if any(_same_identity(juror, conflict) for conflict in conflicts)
    ]
    inactive_ids = [
        juror for juror in panel if not reviewer_lane_active(state, juror, DISPUTE_REVIEW_LANE)
    ]
    impacted = [
        juror for juror in panel if juror in conflict_ids or juror in inactive_ids
    ]
    usable_reserves = [
        juror
        for juror in reserves
        if not any(_same_identity(juror, conflict) for conflict in conflicts)
        and reviewer_lane_active(state, juror, DISPUTE_REVIEW_LANE)
    ]
    replacements = [
        {"original": original, "candidate_substitute": substitute}
        for original, substitute in zip(impacted, usable_reserves, strict=False)
    ]
    remaining = max(0, len(usable_reserves) - len(replacements))
    expected_quorum = quorum_threshold(required)
    if is_explicit_severe_account_sanction(dispute):
        expected_quorum = max(20, expected_quorum)

    result: Json = {
        "status": "unreviewed",
        "authorized": False,
        "dispute_id": dispute_id,
        "gate_version": version,
        "strict_profile": strict,
        "panel_round": dispute.get("panel_round", 1),
        "original_panel_commitment": dispute.get("panel_commitment"),
        "original_panel": panel,
        "original_substitutes": reserves,
        "required_panel_size": required,
        "required_substitute_count": needed_reserves,
        "pinned_required_votes": dispute.get("required_votes"),
        "minimum_required_votes": expected_quorum,
        "conflicted_assigned_jurors": conflict_ids,
        "inactive_assigned_jurors": inactive_ids,
        "replacement_candidates": replacements,
        "unfilled_slots": max(0, len(impacted) - len(replacements)),
        "remaining_eligible_reserves": remaining,
        "reserve_replenishment_required": max(0, needed_reserves - remaining),
        "ballots_already_present": _has_existing_ballots(dispute),
        "original_commitment_provenance_verified": False,
        "automatic_reassignment_enabled": False,
        "reputation_penalty_waiver_authorized": False,
    }
    if not strict:
        result["status"] = "legacy_profile_not_authorized"
    elif type(version) is not int or version not in (1, 2):
        result["status"] = "blocked_unsupported_gate_version"
    elif version != 2:
        result["status"] = "version2_not_activated"
    elif (
        dispute.get("stage") != "juror_review"
        or dispute.get("panel_status") != "assigned"
        or not panel_well_formed
        or not reserve_well_formed
        or len(panel) != required
        or len(reserves) != needed_reserves
        or any(_same_identity(juror, reserve) for juror in panel for reserve in reserves)
        or dispute.get("panel_required_size") != required
        or dispute.get("substitute_required_count") != needed_reserves
        or not isinstance(dispute.get("panel_commitment"), str)
        or len(dispute["panel_commitment"]) != 64
    ):
        result["status"] = "blocked_unverified_original_panel"
    elif (
        type(dispute.get("required_votes")) is not int
        or dispute["required_votes"] < expected_quorum
    ):
        result["status"] = "blocked_original_vote_threshold_drift"
    elif not impacted:
        result["status"] = "original_panel_unchanged"
    elif result["ballots_already_present"]:
        result["status"] = "blocked_existing_ballots"
    elif result["unfilled_slots"]:
        result["status"] = "blocked_insufficient_substitutes"
    else:
        result["status"] = "candidate_requires_constitutional_review"
    return result
