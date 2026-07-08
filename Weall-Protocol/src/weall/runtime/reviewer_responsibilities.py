from __future__ import annotations

from typing import Any

Json = dict[str, Any]

REVIEWER_LANES: tuple[str, ...] = (
    "content_review",
    "dispute_review",
    "poh_async_review",
    "poh_live_review",
)

POH_ASYNC_REVIEW_LANE = "poh_async_review"
POH_TIER2_REVIEW_LANE = "poh_async_review"
POH_LIVE_REVIEW_LANE = "poh_live_review"
DISPUTE_REVIEW_LANE = "dispute_review"
CONTENT_REVIEW_LANE = "content_review"


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value).strip()
    except Exception:
        return ""


def identity_variants(value: Any) -> list[str]:
    s = _as_str(value)
    if not s:
        return []
    base = s[1:] if s.startswith("@") else s
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (s, base, f"@{base}" if base else ""):
        c = _as_str(candidate)
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _matches_identity(account_id: str, values: Any) -> bool:
    variants = set(identity_variants(account_id))
    if not variants:
        return False
    if not isinstance(values, list):
        return False
    for value in values:
        if variants.intersection(identity_variants(value)):
            return True
    return False


def _record_blocked(rec: Any) -> bool:
    if not isinstance(rec, dict):
        return False
    for key in ("banned", "blocked", "disabled", "removed", "replaced", "revoked", "suspended"):
        if bool(rec.get(key)):
            return True
    status = _as_str(rec.get("status")).lower()
    return status in {
        "banned",
        "blocked",
        "declined",
        "disabled",
        "inactive",
        "removed",
        "replaced",
        "retired",
        "revoked",
        "suspended",
    }


def _record_active(rec: Any) -> bool:
    if not isinstance(rec, dict) or _record_blocked(rec):
        return False
    if bool(rec.get("active")) or bool(rec.get("activated")) or bool(rec.get("enabled")):
        return True
    status = _as_str(rec.get("status")).lower()
    return status in {"active", "activated", "enabled", "juror", "live"}


def _role_record_for_identity(mapping: Json, account_id: str) -> Json:
    for variant in identity_variants(account_id):
        rec = mapping.get(variant)
        if isinstance(rec, dict):
            return rec
    return {}


def active_juror_role_record(state: Json, account_id: str) -> Json:
    roles_raw = state.get("roles")
    # Compatibility for old unit fixtures and pre-role-schema bootstrap states:
    # if the ledger has not introduced roles.jurors at all, leave legacy Tier-2
    # case-scoped reviewers to the caller's account/tier checks. Once the Juror
    # namespace exists, review authority becomes explicit and fail-closed.
    if not isinstance(roles_raw, dict) or "jurors" not in roles_raw:
        return {"account_id": _as_str(account_id), "active": True, "legacy_no_juror_namespace": True}
    roles = _as_dict(roles_raw)
    jurors = _as_dict(roles.get("jurors"))
    by_id = _as_dict(jurors.get("by_id"))
    rec = _role_record_for_identity(by_id, account_id)
    if rec and _record_blocked(rec):
        return {}
    if rec and _record_active(rec):
        return rec
    if _matches_identity(account_id, jurors.get("active_set")):
        # Legacy migrated ledgers may have an active-set entry before a by_id
        # record is backfilled. Treat that as a coarse Juror opt-in, but only
        # for the explicit juror role namespace, never for validators/operators.
        return rec if rec else {"account_id": _as_str(account_id), "active": True, "legacy_active_set": True}
    return {}


def reviewer_lane_record(state: Json, account_id: str, lane: str) -> Json:
    lane = _as_str(lane)
    if lane not in REVIEWER_LANES:
        return {}
    rec = active_juror_role_record(state, account_id)
    if not rec:
        return {}
    responsibilities = rec.get("responsibilities")
    # Batch 616 introduced exact per-lane opt-ins. New role transactions now
    # stamp a responsibilities/reviewer object even when no lanes were chosen,
    # which must remain fail-closed. Older ledgers, fixtures, demo seeders, and
    # historical proof harnesses may only have the coarse active Juror role (or
    # the pre-juror-namespace Tier-2 reviewer pool). Treat those records as
    # migrated explicit legacy consent so old state can replay deterministically,
    # but never infer lanes once an exact responsibilities object exists.
    if not isinstance(responsibilities, dict):
        return {
            "legacy_juror_role_opt_in": True,
            "legacy_migration_compat": True,
            "opted_in": True,
            "active": True,
            "lane": lane,
        }
    reviewer = responsibilities.get("reviewer")
    if not isinstance(reviewer, dict):
        return {"legacy_juror_role_opt_in": False, "opted_in": False, "active": False}
    lane_rec = reviewer.get(lane)
    if not isinstance(lane_rec, dict):
        return {"legacy_juror_role_opt_in": False, "opted_in": False, "active": False}
    return lane_rec


def reviewer_lane_active(state: Json, account_id: str, lane: str) -> bool:
    lane_rec = reviewer_lane_record(state, account_id, lane)
    if not lane_rec:
        return False
    if _record_blocked(lane_rec):
        return False
    if lane_rec.get("opted_in") is False:
        return False
    # Exact reviewer lane opt-in is the grant once the Juror role record is
    # active and the lane record is not blocked. Some live/devnet records from
    # earlier builds carried opted_in=true with active=false/activation-pending;
    # treat that as deterministic active availability rather than a second,
    # misleading activation limbo.
    return bool(lane_rec.get("opted_in", True))


def eligible_reviewer_ids(state: Json, lane: str) -> list[str]:
    roles = _as_dict(state.get("roles"))
    jurors = _as_dict(roles.get("jurors"))
    candidates: list[str] = []
    active_set = jurors.get("active_set")
    if isinstance(active_set, list):
        candidates.extend([_as_str(x) for x in active_set if _as_str(x)])
    by_id = _as_dict(jurors.get("by_id"))
    candidates.extend([_as_str(x) for x in by_id.keys() if _as_str(x)])

    out: list[str] = []
    seen: set[str] = set()
    for account_id in sorted(candidates):
        if not account_id or account_id in seen:
            continue
        if reviewer_lane_active(state, account_id, lane):
            seen.add(account_id)
            out.append(account_id)
    return out
