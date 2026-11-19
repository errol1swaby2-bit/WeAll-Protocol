"""Read-only deterministic fresh-appeal panel preview for severe sanctions.

This code is NOT connected to the dispute scheduler, SYSTEM queue, or an
ACCOUNT_BAN producer. Even a plausible panel preview cannot prove juror votes,
case authority, evidence validity, constitutional waiver, or BFT finality.
"""

from __future__ import annotations

import copy
from typing import Any

from weall.runtime.apply.dispute import select_dispute_panel
from weall.runtime.ballot_policy import strict_civic_governance_enabled
from weall.runtime.constitutional_clock import policy_from_state
from weall.runtime.reviewer_responsibilities import (
    DISPUTE_REVIEW_LANE,
    eligible_reviewer_ids,
)
from weall.runtime.severe_sanction_boundary import is_explicit_severe_account_sanction

Json = dict[str, Any]


def _dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item and item == item.strip()]


def _identity_keys(values: list[str]) -> set[str]:
    return {value.removeprefix("@") for value in values}


def _count(value: Any) -> int:
    return value if type(value) is int and 0 <= value <= 25 else -1


def preview_fresh_severe_appeal(state: Json, *, dispute_id: str) -> Json:
    """Evaluate a deterministic appeal roster; unconditionally deny activation.

    Never mutates input state, including when the underlying panel selector
    updates a copied dispute's conflict bookkeeping. No queue entries, votes,
    authorizations, or semantic-review attestations are created.
    """
    state_copy = copy.deepcopy(state)
    dispute = _dict(_dict(state_copy.get("disputes_by_id")).get(dispute_id))
    reasons: list[str] = []
    if not policy_from_state(state_copy).enabled:
        reasons.append("constitutional_clock_not_active")
    if not strict_civic_governance_enabled(state_copy):
        reasons.append("strict_civic_profile_not_active")
    if not dispute:
        reasons.append("dispute_not_found")
    if not is_explicit_severe_account_sanction(dispute):
        reasons.append("canonical_severe_account_class_not_established")

    initial = _ids(dispute.get("assigned_jurors"))
    substitutes = _ids(dispute.get("substitute_juror_ids"))
    if len(initial) != 25 or len(_identity_keys(initial)) != 25:
        reasons.append("initial_panel_not_25_distinct")
    if len(substitutes) != 5 or len(_identity_keys(substitutes)) != 5:
        reasons.append("initial_substitutes_not_5_distinct")
    if _identity_keys(initial).intersection(_identity_keys(substitutes)):
        reasons.append("initial_panel_substitute_overlap")
    if dispute.get("panel_status") != "assigned" or not dispute.get("panel_commitment"):
        reasons.append("initial_panel_assignment_unverified")

    tally = _dict(dispute.get("vote_counts"))
    yes = _count(tally.get("yes"))
    no = _count(tally.get("no"))
    if (
        yes < 20
        or no < 0
        or yes + no > 25
        or _dict(dispute.get("resolution")).get("outcome") != "report_upheld"
        or dispute.get("resolved") is not True
    ):
        reasons.append("initial_twenty_yes_not_observed")

    selection: Json = {}
    # Avoid generating a plausible candidate if the originating decision,
    # panel, or strict clock profile is structurally incomplete.
    if not reasons:
        candidates = eligible_reviewer_ids(state_copy, DISPUTE_REVIEW_LANE)
        selection = select_dispute_panel(
            state_copy,
            dispute,
            candidates,
            round_no=2,
            exclude_ids=initial + substitutes,
        )
        fresh = _ids(selection.get("panel"))
        fresh_subs = _ids(selection.get("substitutes"))
        previous = _identity_keys(initial + substitutes)
        new = _identity_keys(fresh + fresh_subs)
        if (
            selection.get("status") != "assigned"
            or selection.get("strict") is not True
            or selection.get("required_panel_size") != 25
            or selection.get("required_substitute_count") != 5
            or len(fresh) != 25
            or len(fresh_subs) != 5
            or len(new) != 30
            or bool(previous.intersection(new))
        ):
            reasons.append("fresh_appeal_pool_incomplete_or_not_independent")

    return {
        "schema": "weall.severe-appeal-preview.v0",
        "status": "BLOCKED_REVIEW_ONLY",
        "dispute_id": dispute_id,
        "initial_yes_observed": yes,
        "candidate_panel_complete": not reasons,
        "panel": list(selection.get("panel") or []),
        "substitutes": list(selection.get("substitutes") or []),
        "panel_commitment": selection.get("panel_commitment", ""),
        "structural_blockers": reasons,
        "authorization_blockers": [
            "case_severity_not_cryptographically_authenticated",
            "initial_vote_tally_not_independently_authenticated",
            "fresh_appeal_not_issued_or_voted",
            "system_receipt_provenance_not_verified",
            "consensus_activation_and_historical_replay_unapproved",
        ],
        "may_enqueue_account_ban": False,
        "may_finalize_severe_sanction": False,
    }
