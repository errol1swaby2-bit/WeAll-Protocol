from __future__ import annotations

"""Deterministic reviewer selection and conflict checks for account recovery.

The module is consensus-safe: it consumes only canonical state, the request id,
and account identifiers.  It never consults wall clock, network, environment, or
provider-local data.
"""

import hashlib
from typing import Any

from weall.runtime.poh.state import effective_poh_tier
from weall.runtime.reviewer_responsibilities import (
    POH_ASYNC_REVIEW_LANE,
    eligible_reviewer_ids,
    reviewer_lane_active,
)

Json = dict[str, Any]

CONTINUITY_PANEL_SIZE = 15
CONTINUITY_APPROVAL_THRESHOLD = 10
REVERSAL_PANEL_SIZE = 25
REVERSAL_APPROVAL_THRESHOLD = 20
RECOVERY_REVIEW_WINDOW_BLOCKS = 43_200


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _account(state: Json, account_id: str) -> Json:
    accounts = _as_dict(state.get("accounts"))
    rec = accounts.get(_as_str(account_id))
    return rec if isinstance(rec, dict) else {}


def _identity_set(value: Any) -> set[str]:
    return {_as_str(item) for item in _as_list(value) if _as_str(item)}


def _institution_ids(account: Json) -> set[str]:
    out = _identity_set(account.get("institutional_affiliations"))
    out.update(_identity_set(account.get("institution_ids")))
    institution_id = _as_str(account.get("institution_id"))
    if institution_id:
        out.add(institution_id)
    return out


def recovery_conflict_reason(
    state: Json,
    *,
    reviewer_id: str,
    target_id: str,
    excluded_reviewers: set[str] | None = None,
) -> str | None:
    reviewer_id = _as_str(reviewer_id)
    target_id = _as_str(target_id)
    if not reviewer_id or not target_id:
        return "missing_identity"
    if reviewer_id == target_id:
        return "self_review"
    if excluded_reviewers and reviewer_id in excluded_reviewers:
        return "prior_case_reviewer"

    reviewer = _account(state, reviewer_id)
    target = _account(state, target_id)
    if not reviewer or not target:
        return "unknown_account"
    if reviewer.get("account_type") == "institution" or target.get("account_type") == "institution":
        return "institutional_account"
    if bool(reviewer.get("banned")) or bool(reviewer.get("locked")):
        return "reviewer_unavailable"
    if effective_poh_tier(state, reviewer_id) < 2:
        return "reviewer_tier2_required"
    if not reviewer_lane_active(state, reviewer_id, POH_ASYNC_REVIEW_LANE):
        return "reviewer_lane_required"

    reviewer_household = _as_str(reviewer.get("household_id"))
    target_household = _as_str(target.get("household_id"))
    if reviewer_household and target_household and reviewer_household == target_household:
        return "shared_household"

    reviewer_financial = _identity_set(reviewer.get("financial_dependencies"))
    target_financial = _identity_set(target.get("financial_dependencies"))
    if target_id in reviewer_financial or reviewer_id in target_financial:
        return "financial_dependency"

    reviewer_conflicts = _identity_set(reviewer.get("conflicts"))
    target_conflicts = _identity_set(target.get("conflicts"))
    if target_id in reviewer_conflicts or reviewer_id in target_conflicts:
        return "declared_conflict"

    if _institution_ids(reviewer).intersection(_institution_ids(target)):
        return "shared_institution"
    return None


def select_recovery_reviewers(
    state: Json,
    *,
    request_id: str,
    target_id: str,
    panel_size: int,
    excluded_reviewers: set[str] | None = None,
) -> list[str]:
    request_id = _as_str(request_id)
    target_id = _as_str(target_id)
    panel_size = max(1, int(panel_size))
    excluded = set(excluded_reviewers or set())
    pool: list[str] = []
    for reviewer_id in eligible_reviewer_ids(state, POH_ASYNC_REVIEW_LANE):
        if recovery_conflict_reason(
            state,
            reviewer_id=reviewer_id,
            target_id=target_id,
            excluded_reviewers=excluded,
        ) is None:
            pool.append(reviewer_id)
    if len(pool) < panel_size:
        return []
    chain_id = _as_str(state.get("chain_id") or _as_dict(state.get("params")).get("chain_id"))
    scored = []
    for reviewer_id in pool:
        digest = hashlib.sha256(
            f"{chain_id}|RECOVERY_REVIEW|{request_id}|{target_id}|{reviewer_id}".encode("utf-8")
        ).hexdigest()
        scored.append((digest, reviewer_id))
    scored.sort()
    return [reviewer_id for _digest, reviewer_id in scored[:panel_size]]


def review_counts(request: Json) -> tuple[int, int, int]:
    reviews = _as_dict(request.get("reviews"))
    approvals = 0
    rejections = 0
    for raw in reviews.values():
        rec = _as_dict(raw)
        decision = _as_str(rec.get("decision")).lower()
        if decision == "approve":
            approvals += 1
        elif decision == "reject":
            rejections += 1
    return approvals, rejections, approvals + rejections


__all__ = [
    "CONTINUITY_APPROVAL_THRESHOLD",
    "CONTINUITY_PANEL_SIZE",
    "RECOVERY_REVIEW_WINDOW_BLOCKS",
    "REVERSAL_APPROVAL_THRESHOLD",
    "REVERSAL_PANEL_SIZE",
    "recovery_conflict_reason",
    "review_counts",
    "select_recovery_reviewers",
]
