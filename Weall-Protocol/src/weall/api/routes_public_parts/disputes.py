# src/weall/api/routes_public_parts/disputes.py
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _cursor_pack, _cursor_unpack, _int_param, _read_json_limited, _snapshot
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


def _same_identity(a: Any, b: Any) -> bool:
    av = _identity_variants(a)
    bv = _identity_variants(b)
    return bool(av and bv and any(x == y for x in av for y in bv))


def _content_target_owner(st: dict[str, Any], *, target_type: str, target_id: str) -> str:
    if str(target_type or "").strip().lower() not in {"content", "post", "comment"}:
        return ""
    tid = str(target_id or "").strip()
    content = _as_dict(st.get("content"))
    for bucket_name in ("posts", "comments"):
        bucket = _as_dict(content.get(bucket_name))
        rec = _as_dict(bucket.get(tid))
        if not rec:
            continue
        return str(
            rec.get("author")
            or rec.get("owner")
            or rec.get("account_id")
            or rec.get("created_by")
            or rec.get("signer")
            or ""
        ).strip()
    return ""


def _resolved_target_owner(st: dict[str, Any], obj: dict[str, Any]) -> str:
    owner = str(obj.get("target_owner") or obj.get("target_author") or "").strip()
    if owner:
        return owner
    return _content_target_owner(
        st,
        target_type=str(obj.get("target_type") or "content"),
        target_id=str(obj.get("target_id") or ""),
    )


def _appeal_allowed_accounts(st: dict[str, Any], obj: dict[str, Any]) -> list[str]:
    raw = obj.get("appeal_allowed_accounts")
    out: list[str] = []
    if isinstance(raw, list):
        out.extend(str(x or "").strip() for x in raw if str(x or "").strip())
    owner = _resolved_target_owner(st, obj)
    if owner:
        out.append(owner)
    seen: set[str] = set()
    normalized: list[str] = []
    for acct in out:
        key = acct.lstrip("@")
        if not key or key in seen:
            continue
        seen.add(key)
        normalized.append(acct)
    return normalized


def _appeal_eligibility(st: dict[str, Any], obj: dict[str, Any], *, viewer: str) -> dict[str, Any]:
    allowed = _appeal_allowed_accounts(st, obj)
    stage = str(obj.get("stage") or "open").strip().lower()
    can_window = stage in {"appeal_window", "appealed", "appeal_review"}
    can_actor = bool(viewer and allowed and any(_same_identity(viewer, acct) for acct in allowed))
    return {
        "viewer": viewer or None,
        "can_file": bool(can_window and can_actor),
        "reason": "eligible_target_owner" if can_window and can_actor else ("not_target_owner" if can_window and allowed else "appeal_window_not_open"),
        "allowed_accounts": allowed,
        "target_owner": allowed[0] if allowed else None,
    }


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



def _viewer_vote_record(obj: dict[str, Any], viewer: str) -> dict[str, Any]:
    """Expose only the caller's own vote while keeping global vote maps redacted."""

    if not viewer:
        return {}
    variants = _identity_variants(viewer)
    votes = _as_dict(obj.get("votes"))
    for variant in variants:
        rec = votes.get(variant)
        if isinstance(rec, dict):
            out = dict(rec)
            out.setdefault("account", variant)
            out.setdefault("juror", variant)
            return out
    return {}


def _vote_choice_from_record(record: dict[str, Any]) -> str:
    choice = str(
        record.get("vote")
        or record.get("choice")
        or record.get("decision")
        or record.get("outcome")
        or ""
    ).strip().lower()
    if choice:
        return choice
    resolution = _as_dict(record.get("resolution"))
    return str(resolution.get("outcome") or resolution.get("action") or "").strip().lower()

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
        choice = _vote_choice_from_record(record)
        if choice in {"yes", "remove", "removed", "uphold", "upheld", "report_upheld"}:
            vote_counts["yes"] += 1
        elif choice in {"no", "keep", "kept", "dismiss", "dismissed", "report_not_upheld"}:
            vote_counts["no"] += 1
        elif choice:
            vote_counts["abstain"] += 1

    juror_counts = {"assigned": 0, "accepted": 0, "declined": 0, "present": 0, "withdrawn": 0, "timed_out": 0, "completed": 0}
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




def _redact_dispute_detail_maps(obj: dict[str, Any], *, viewer: str = "", st: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return dispute detail/list shape without unbounded maps/lists."""

    st = st if isinstance(st, dict) else {}
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
        review_deadline = int(viewer_juror.get("vote_deadline_height") or 0)
        normalized["canonical_deadlines"] = {
            "accepted_at_height": int(viewer_juror.get("accepted_at_height") or viewer_juror.get("accepted_at_block_height") or 0),
            "review_deadline_height": review_deadline,
            "vote_deadline_height": review_deadline,
            "safe_withdraw_until_height": int(viewer_juror.get("safe_withdraw_until_height") or 0),
            "clock": "block_height",
        }
        normalized["reputation_warning"] = {
            "text": "Accepting this dispute creates a 1-hour review obligation. Withdraw within 15 minutes with no reputation impact. Late withdrawal causes a small juror reliability penalty. Timeout causes a larger juror reliability penalty.",
            "frontend_classifies_penalty": False,
            "backend_source_of_truth": True,
            "dimension": "juror_reputation",
        }
    normalized["counts_total"] = {
        "jurors": len(jurors),
        "votes": len(votes),
        "evidence": len(evidence),
        "appeals": len(appeals),
    }
    viewer_vote = _viewer_vote_record(obj, viewer)
    if viewer_vote:
        normalized["viewer_vote"] = viewer_vote
        normalized["current_vote"] = viewer_vote
        normalized["vote_self"] = viewer_vote
    target_owner = _resolved_target_owner(st, obj)
    if target_owner:
        # Keep owner/appeal identity in the redacted dispute record even when the
        # disputed content has already been hidden from normal content reads. The
        # affected creator should not have to fetch removed content to see or file
        # their appeal.
        normalized["target_owner"] = target_owner
        normalized["target_author"] = target_owner
    normalized["appeal_allowed_accounts"] = _appeal_allowed_accounts(st, obj)
    normalized["appeal_eligibility"] = _appeal_eligibility(st, obj, viewer=viewer)
    return normalized


def _redact_dispute_detail_for_viewer(
    obj: dict[str, Any],
    *,
    viewer: str = "",
    st: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Redact global maps while preserving Batch 389 viewer-scope invariant.

    Batch 448 needs chain-state context to expose creator appeal eligibility even
    after target content is hidden from normal reads. Keep the historical
    redaction call shape intact so older scope guards continue to prove the API
    redacts global juror/vote/evidence/appeal maps before adding viewer-safe
    appeal context.
    """

    normalized = _redact_dispute_detail_maps(obj, viewer=viewer)
    st = st if isinstance(st, dict) else {}

    target_owner = _resolved_target_owner(st, obj)
    if target_owner:
        normalized["target_owner"] = target_owner
        normalized["target_author"] = target_owner
    normalized["appeal_allowed_accounts"] = _appeal_allowed_accounts(st, obj)
    normalized["appeal_eligibility"] = _appeal_eligibility(st, obj, viewer=viewer)
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



def _status_for_viewer(obj: dict[str, Any], viewer: str) -> str:
    return str(_viewer_juror_record(obj, viewer).get("status") or "unassigned").strip().lower() or "unassigned"


def _dispute_ineligibility_reasons(st: dict[str, Any], obj: dict[str, Any], viewer: str) -> list[str]:
    reasons: list[str] = []
    if not viewer:
        reasons.append("account_session_required")
        return reasons
    normalized = _normalize_dispute(obj)
    if not _is_active_stage(str(normalized.get("stage") or "open")):
        reasons.append("dispute_not_active")
    opened_by = str(normalized.get("opened_by") or normalized.get("reporter") or "").strip()
    if opened_by and _same_identity(viewer, opened_by):
        reasons.append("reporter_or_opener_conflict")
    target_owner = _resolved_target_owner(st, normalized)
    if target_owner and _same_identity(viewer, target_owner):
        reasons.append("target_owner_conflict")
    accused = str(normalized.get("accused") or normalized.get("accused_account") or normalized.get("target_account") or "").strip()
    if accused and _same_identity(viewer, accused):
        reasons.append("accused_actor_conflict")
    eligible = normalized.get("eligible_juror_ids")
    if isinstance(eligible, list) and eligible:
        if not any(_same_identity(viewer, item) for item in eligible):
            reasons.append("not_in_canonical_eligible_juror_snapshot")
    status = _status_for_viewer(normalized, viewer)
    if status in {"accepted", "present", "attended", "completed"}:
        reasons.append("already_current_assignment")
    elif status in {"withdrawn", "timed_out", "declined"}:
        reasons.append(f"assignment_{status}")
    return sorted(set(reasons))


def _dispute_tx_template(*, tx_type: str, signer: str, dispute_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = dict(payload or {})
    body.setdefault("dispute_id", dispute_id)
    return {
        "tx_type": tx_type,
        "signer": signer,
        "payload": body,
        "submit_path": "/v1/tx/submit",
        "requires_client_signature": True,
        "mutation_boundary": "template_only_no_state_mutation_until_signed_tx_finalizes",
    }


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
        items.append(_redact_dispute_detail_for_viewer(obj, viewer=viewer, st=st))

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



@router.get("/disputes/eligible")
def v1_disputes_eligible(request: Request):
    st = _snapshot(request)
    viewer = str(require_account_session(request, st) or "").strip()
    items: list[dict[str, Any]] = []
    for _, obj in sorted(_disputes_by_id(st).items(), key=lambda item: str(item[0])):
        if not isinstance(obj, dict):
            continue
        reasons = _dispute_ineligibility_reasons(st, obj, viewer)
        if reasons:
            continue
        redacted = _redact_dispute_detail_for_viewer(obj, viewer=viewer, st=st)
        redacted["eligibility"] = {"eligible": True, "reasons": ["eligible"], "backend_source_of_truth": True}
        items.append(redacted)
    items.sort(key=lambda x: (int(x.get("canonical_deadlines", {}).get("review_deadline_height") or 0), str(x.get("id") or "")))
    return {"ok": True, "account_id": viewer, "items": items, "count": len(items)}


@router.get("/disputes/current")
def v1_disputes_current(request: Request):
    st = _snapshot(request)
    viewer = str(require_account_session(request, st) or "").strip()
    items: list[dict[str, Any]] = []
    for _, obj in sorted(_disputes_by_id(st).items(), key=lambda item: str(item[0])):
        if not isinstance(obj, dict):
            continue
        status = _status_for_viewer(obj, viewer)
        if status not in {"assigned", "accepted", "present", "attended", "completed"}:
            continue
        redacted = _redact_dispute_detail_for_viewer(obj, viewer=viewer, st=st)
        deadlines = _as_dict(redacted.get("canonical_deadlines"))
        redacted["assignment_status"] = status
        redacted["next_action"] = "vote" if status in {"accepted", "present", "attended"} else ("accept_or_decline" if status == "assigned" else "completed")
        redacted["backend_source_of_truth"] = True
        redacted["deadline_sort_height"] = int(deadlines.get("review_deadline_height") or 0)
        items.append(redacted)
    items.sort(key=lambda x: (int(x.get("deadline_sort_height") or 0), str(x.get("id") or "")))
    return {"ok": True, "account_id": viewer, "items": items, "count": len(items)}


@router.post("/disputes/{dispute_id}/accept")
def v1_dispute_accept(dispute_id: str, request: Request):
    st = _snapshot(request)
    viewer = str(require_account_session(request, st) or "").strip()
    obj = _dispute_obj_from_snapshot(st, dispute_id)
    reasons = _dispute_ineligibility_reasons(st, obj, viewer)
    allowed = not reasons or reasons == ["already_current_assignment"]
    return {
        "ok": bool(allowed),
        "account_id": viewer,
        "dispute_id": dispute_id,
        "eligible": bool(allowed),
        "reasons": reasons or ["eligible"],
        "warning": "Accepting this dispute creates a 1-hour review obligation. Withdraw within 15 minutes with no reputation impact. Late withdrawal causes a small juror reliability penalty. Timeout causes a larger juror reliability penalty.",
        "deterministic_source": "signed_tx_submit",
        "tx": _dispute_tx_template(tx_type="DISPUTE_JUROR_ACCEPT", signer=viewer, dispute_id=dispute_id),
        "tx_template": _dispute_tx_template(tx_type="DISPUTE_JUROR_ACCEPT", signer=viewer, dispute_id=dispute_id),
    }


@router.post("/disputes/{dispute_id}/withdraw")
def v1_dispute_withdraw(dispute_id: str, request: Request):
    st = _snapshot(request)
    viewer = str(require_account_session(request, st) or "").strip()
    obj = _dispute_obj_from_snapshot(st, dispute_id)
    status = _status_for_viewer(obj, viewer)
    allowed = status in {"accepted", "present", "attended"}
    return {
        "ok": bool(allowed),
        "account_id": viewer,
        "dispute_id": dispute_id,
        "eligible": bool(allowed),
        "reasons": ["eligible"] if allowed else [f"status_{status}_cannot_withdraw"],
        "backend_classifies_penalty": True,
        "frontend_classifies_penalty": False,
        "deterministic_source": "signed_tx_submit",
        "tx": _dispute_tx_template(tx_type="DISPUTE_JUROR_WITHDRAW", signer=viewer, dispute_id=dispute_id),
        "tx_template": _dispute_tx_template(tx_type="DISPUTE_JUROR_WITHDRAW", signer=viewer, dispute_id=dispute_id),
    }


@router.post("/disputes/{dispute_id}/vote")
async def v1_dispute_vote(dispute_id: str, request: Request):
    st = _snapshot(request)
    viewer = str(require_account_session(request, st) or "").strip()
    obj = _dispute_obj_from_snapshot(st, dispute_id)
    status = _status_for_viewer(obj, viewer)
    body = await _read_json_limited(request, max_bytes_env="WEALL_MAX_HTTP_DISPUTE_ACTION_BYTES", default_max_bytes=64 * 1024)
    payload = body if isinstance(body, dict) else {}
    payload.setdefault("dispute_id", dispute_id)
    viewer_juror = _viewer_juror_record(obj, viewer)
    attendance = viewer_juror.get("attendance") if isinstance(viewer_juror, dict) else None
    attendance_present = (isinstance(attendance, dict) and bool(attendance.get("present", False))) or status in {"present", "attended"}
    allowed = status in {"accepted", "present", "attended"} and attendance_present
    if allowed:
        reasons = ["eligible"]
    elif status == "assigned":
        reasons = ["acceptance_required", "attendance_required"]
    elif status == "accepted" and not attendance_present:
        reasons = ["attendance_required"]
    else:
        reasons = [f"status_{status}_cannot_vote"]
    return {
        "ok": bool(allowed),
        "account_id": viewer,
        "dispute_id": dispute_id,
        "eligible": bool(allowed),
        "reasons": reasons,
        "requires_acceptance": bool(status == "assigned"),
        "requires_attendance": bool(not attendance_present),
        "backend_classifies_deadline": True,
        "frontend_classifies_penalty": False,
        "deterministic_source": "signed_tx_submit",
        "tx": _dispute_tx_template(tx_type="DISPUTE_VOTE_SUBMIT", signer=viewer, dispute_id=dispute_id, payload=payload),
        "tx_template": _dispute_tx_template(tx_type="DISPUTE_VOTE_SUBMIT", signer=viewer, dispute_id=dispute_id, payload=payload),
    }


@router.get("/disputes/{dispute_id}")
def v1_dispute_get(dispute_id: str, request: Request):
    st = _snapshot(request)
    obj = _dispute_obj_from_snapshot(st, dispute_id)
    viewer = _viewer_from_request(request, st)
    return {"ok": True, "dispute": _redact_dispute_detail_for_viewer(obj, viewer=viewer, st=st)}


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
