# src/weall/api/routes_public_parts/disputes.py
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _cursor_pack, _cursor_unpack, _int_param, _snapshot
from weall.api.security import require_account_session

router = APIRouter()


def _is_active_stage(stage: str) -> bool:
    s = str(stage or "").strip().lower()
    if not s:
        return True
    return s not in {"resolved", "closed", "finalized", "dismissed", "expired"}


def _disputes_by_id(st: dict[str, Any]) -> dict[str, Any]:
    by_id = st.get("disputes_by_id")
    if isinstance(by_id, dict):
        return by_id
    return {}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}





def _identity_variants(value: Any) -> list[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    base = raw[1:] if raw.startswith("@") else raw
    out: list[str] = []
    for candidate in (raw, base, f"@{base}" if base else ""):
        c = str(candidate or "").strip()
        if c and c not in out:
            out.append(c)
    return out


def _viewer_from_request(request: Request, st: dict[str, Any]) -> str:
    try:
        return str(require_account_session(request, st) or "").strip()
    except Exception:
        return ""


def _viewer_juror_record(obj: dict[str, Any], viewer: str) -> dict[str, Any]:
    if not viewer:
        return {}
    variants = _identity_variants(viewer)
    jurors = _as_dict(obj.get("jurors"))
    for variant in variants:
        rec = jurors.get(variant)
        if isinstance(rec, dict):
            out = dict(rec)
            out.setdefault("account", variant)
            out.setdefault("juror", variant)
            return out

    assigned = obj.get("assigned_jurors")
    if isinstance(assigned, list):
        for candidate in assigned:
            c = str(candidate or "").strip()
            if c and any(c == v for v in variants):
                return {"account": c, "juror": c, "status": "assigned"}

    # Older/system-escalated report states may expose the reviewer only through
    # eligible_juror_ids until the queued assignment receipt is replayed. Keep
    # global juror maps redacted, but let the logged-in reviewer see their own
    # actionable assignment so accept/vote controls do not remain locked.
    eligible = obj.get("eligible_juror_ids")
    if isinstance(eligible, list):
        for candidate in eligible:
            c = str(candidate or "").strip()
            if c and any(c == v for v in variants):
                return {"account": c, "juror": c, "status": "assigned", "source": "eligible_juror_ids"}
    return {"account": viewer, "juror": viewer, "status": "unassigned"}

def _page_vote_map(votes: dict[str, Any], *, limit: int, cursor: Any) -> tuple[dict[str, Any], str | None]:
    _cursor_n, cursor_key = _cursor_unpack(cursor)
    rows = [(str(k), v) for k, v in votes.items()]
    rows.sort(key=lambda item: item[0])
    if cursor_key:
        rows = [item for item in rows if item[0] > cursor_key]
    page_rows = rows[:limit]
    next_cursor = None
    if len(page_rows) == limit:
        next_cursor = _cursor_pack(created_at_nonce=0, content_id=page_rows[-1][0])
    return {k: v for k, v in page_rows}, next_cursor
def _normalize_dispute(obj: dict[str, Any]) -> dict[str, Any]:
    out = dict(obj)
    dispute_id = str(out.get("id") or out.get("dispute_id") or "").strip()
    stage = str(out.get("stage") or "open").strip() or "open"
    opened_by = str(out.get("opened_by") or out.get("opened_by_account") or "").strip()
    target_type = str(out.get("target_type") or "content").strip() or "content"
    target_id = str(out.get("target_id") or "").strip()
    jurors = _as_dict(out.get("jurors"))
    votes = _as_dict(out.get("votes"))
    evidence = out.get("evidence") if isinstance(out.get("evidence"), list) else []
    appeals = out.get("appeals") if isinstance(out.get("appeals"), list) else []

    vote_counts = {"yes": 0, "no": 0, "abstain": 0}
    for _, record in sorted(votes.items(), key=lambda item: str(item[0])):
        if not isinstance(record, dict):
            continue
        choice = str(record.get("vote") or "").strip().lower()
        if choice == "yes":
            vote_counts["yes"] += 1
        elif choice == "no":
            vote_counts["no"] += 1
        elif choice:
            vote_counts["abstain"] += 1

    juror_counts = {"assigned": 0, "accepted": 0, "declined": 0, "present": 0}
    for _, record in sorted(jurors.items(), key=lambda item: str(item[0])):
        if not isinstance(record, dict):
            continue
        status = str(record.get("status") or "assigned").strip().lower() or "assigned"
        if status in juror_counts:
            juror_counts[status] += 1
        attendance = record.get("attendance")
        if isinstance(attendance, dict) and bool(attendance.get("present", False)):
            juror_counts["present"] += 1

    out["id"] = dispute_id
    out.setdefault("dispute_id", dispute_id)
    out["stage"] = stage
    out.setdefault("status", stage)
    out["opened_by"] = opened_by
    out["target_type"] = target_type
    out["target_id"] = target_id
    out["jurors"] = jurors
    out["votes"] = votes
    out["evidence"] = evidence
    out["appeals"] = appeals
    out["resolved"] = bool(out.get("resolved", False))
    out["resolution"] = out.get("resolution")
    out["vote_counts"] = vote_counts
    out["vote_total"] = int(sum(vote_counts.values()))
    out["juror_counts"] = juror_counts
    out["juror_total"] = int(len(jurors))
    out["evidence_total"] = int(len(evidence))
    out["appeal_total"] = int(len(appeals))
    return out




def _redact_dispute_detail_maps(obj: dict[str, Any], *, viewer: str = "") -> dict[str, Any]:
    """Return dispute detail/list shape without unbounded maps/lists."""

    normalized = _normalize_dispute(obj)
    jurors = _as_dict(normalized.get("jurors"))
    votes = _as_dict(normalized.get("votes"))
    evidence = normalized.get("evidence") if isinstance(normalized.get("evidence"), list) else []
    appeals = normalized.get("appeals") if isinstance(normalized.get("appeals"), list) else []
    normalized.pop("jurors", None)
    normalized.pop("votes", None)
    normalized.pop("evidence", None)
    normalized.pop("appeals", None)
    normalized["jurors_redacted"] = True
    normalized["votes_redacted"] = True
    normalized["evidence_redacted"] = True
    normalized["appeals_redacted"] = True
    viewer_juror = _viewer_juror_record(obj, viewer)
    if viewer_juror:
        # Keep the global juror map redacted, but expose the caller's own
        # assignment record so the normal review UI can enable accept/vote
        # controls without leaking other reviewers.
        normalized["viewer_juror"] = viewer_juror
        normalized["current_juror"] = viewer_juror
        normalized["juror_self"] = viewer_juror
    normalized["counts_total"] = {
        "jurors": len(jurors),
        "votes": len(votes),
        "evidence": len(evidence),
        "appeals": len(appeals),
    }
    return normalized

def _dispute_obj_from_snapshot(st: dict[str, Any], dispute_id: str) -> dict[str, Any]:
    by_id = _disputes_by_id(st)
    if not by_id:
        raise ApiError.not_found("not_found", "Dispute not found")

    obj = by_id.get(dispute_id)
    if isinstance(obj, dict):
        return obj

    for _, value in by_id.items():
        if not isinstance(value, dict):
            continue
        candidate = str(value.get("id") or value.get("dispute_id") or "").strip()
        if candidate == dispute_id:
            return value

    raise ApiError.not_found("not_found", "Dispute not found")


@router.get("/disputes")
def v1_disputes_list(request: Request):
    st = _snapshot(request)
    viewer = _viewer_from_request(request, st)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 50)
    limit = max(1, min(200, limit))
    target_id = str(qp.get("target_id") or "").strip()
    stage = str(qp.get("stage") or "").strip().lower()
    active_only = str(qp.get("active_only") or "").strip().lower() in {"1", "true", "yes", "on"}
    include_summary = str(qp.get("include_summary") or "").strip().lower() in {"1", "true", "yes", "on"}

    by_id = _disputes_by_id(st)
    if not by_id:
        return {"ok": True, "items": [], "summary": {"total": 0, "active": 0, "resolved": 0}}

    items: list[dict[str, Any]] = []
    active_count = 0
    resolved_count = 0
    for _, obj in by_id.items():
        if not isinstance(obj, dict):
            continue
        normalized = _normalize_dispute(obj)
        normalized_stage = str(normalized.get("stage") or "open").strip().lower()
        is_active = _is_active_stage(normalized_stage)
        if is_active:
            active_count += 1
        else:
            resolved_count += 1
        if target_id and str(normalized.get("target_id") or "").strip() != target_id:
            continue
        if stage and normalized_stage != stage:
            continue
        if active_only and not is_active:
            continue
        items.append(_redact_dispute_detail_maps(obj, viewer=viewer))

    items.sort(
        key=lambda x: (
            0 if _is_active_stage(str(x.get("stage") or "open")) else 1,
            -int(x.get("opened_at_nonce", 0) or 0),
            str(x.get("id") or ""),
        )
    )
    payload: dict[str, Any] = {"ok": True, "items": items[:limit]}
    if include_summary:
        payload["summary"] = {"total": len(by_id), "active": active_count, "resolved": resolved_count}
    return payload


@router.get("/disputes/{dispute_id}")
def v1_dispute_get(dispute_id: str, request: Request):
    st = _snapshot(request)
    obj = _dispute_obj_from_snapshot(st, dispute_id)
    viewer = _viewer_from_request(request, st)
    return {"ok": True, "dispute": _redact_dispute_detail_maps(obj, viewer=viewer)}


@router.get("/disputes/{dispute_id}/votes")
def v1_dispute_votes(dispute_id: str, request: Request):
    st = _snapshot(request)
    obj = _normalize_dispute(_dispute_obj_from_snapshot(st, dispute_id))
    votes_all = _as_dict(obj.get("votes"))
    qp = request.query_params
    limit = max(1, min(500, _int_param(qp.get("limit"), 100)))
    votes, next_cursor = _page_vote_map(votes_all, limit=limit, cursor=qp.get("cursor"))
    return {
        "ok": True,
        "dispute_id": str(obj.get("id") or dispute_id),
        "stage": str(obj.get("stage") or "open"),
        "votes": votes,
        "vote_counts": obj.get("vote_counts") or {"yes": 0, "no": 0, "abstain": 0},
        "next_cursor": next_cursor,
        "counts_total": {"votes": len(votes_all), "returned_votes": len(votes)},
    }
