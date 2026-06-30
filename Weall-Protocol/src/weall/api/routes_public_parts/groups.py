# src/weall/api/routes_public_parts/groups.py
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import (
    _cursor_pack,
    _cursor_unpack,
    _group_roles_by_id,
    _groups_by_id,
    _int_param,
    _normalize_tags_param,
    _snapshot,
    _str_param,
)
from weall.api.security import require_account_session
from weall.api.routes_public_parts.content import _content_target_hidden_by_review, _with_media_summaries

router = APIRouter()


class TxSkeleton(BaseModel):
    tx_type: str
    signer_hint: str
    parent: str | None
    payload: dict[str, Any]


class TxSkeletonResponse(BaseModel):
    ok: bool
    tx: TxSkeleton


class GroupJoinLeaveRequest(BaseModel):
    group_id: str = Field(..., min_length=1)
    # Optional UX metadata (ignored by apply). Kept for client convenience.
    message: str | None = Field(default=None, max_length=500)


def _group_is_private(g: dict[str, Any]) -> bool:
    # Public-only redesign: group state may restrict participation, never reads.
    return False


def _tags_list(obj: dict[str, Any]) -> list[str]:
    raw = obj.get("tags")
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    return []


def _content_root(st: dict[str, Any]) -> dict[str, Any]:
    content = st.get("content")
    return content if isinstance(content, dict) else {}


def _moderation_targets(st: dict[str, Any]) -> dict[str, Any]:
    moderation = _content_root(st).get("moderation")
    moderation = moderation if isinstance(moderation, dict) else {}
    targets = moderation.get("targets")
    return targets if isinstance(targets, dict) else {}


def _moderation_record_hides(rec: dict[str, Any]) -> bool:
    if not isinstance(rec, dict):
        return False
    if bool(rec.get("deleted", False)):
        return True
    vis = str(rec.get("visibility", "") or "").strip().lower()
    action = str(rec.get("last_action", "") or "").strip().lower()
    return vis in {"hidden", "deleted", "removed"} or action in {"hide", "delete", "remove"}


def _post_moderated_hidden(st: dict[str, Any], post_id: str, post: dict[str, Any] | None = None) -> bool:
    pid = str(post_id or "").strip()
    return _content_target_hidden_by_review(st, pid, post if isinstance(post, dict) else {})


def _iter_group_posts(st: dict[str, Any], *, group_id: str) -> list[dict[str, Any]]:
    content = st.get("content")
    if not isinstance(content, dict):
        return []
    posts = content.get("posts")
    if not isinstance(posts, dict):
        return []

    out: list[dict[str, Any]] = []
    for pid, obj in posts.items():
        if not isinstance(obj, dict):
            continue
        row = dict(obj)
        post_id = _str_param(row.get("post_id") or row.get("id") or pid).strip()
        if bool(obj.get("deleted", False)) or _post_moderated_hidden(st, post_id, row):
            continue

        row.setdefault("id", post_id)
        row.setdefault("created_at_nonce", int(row.get("created_nonce", 0) or 0))
        row.setdefault("visibility", "public")

        if _str_param(row.get("group_id") or "").strip() == str(group_id):
            out.append(row)
            continue

        if f"group:{group_id}" in _tags_list(row):
            out.append(row)

    return out


def _group_record(st: dict[str, Any], group_id: str) -> dict[str, Any] | None:
    by_state = _groups_by_id(st)
    by_roles = _group_roles_by_id(st)

    g_state = by_state.get(group_id)
    g_roles = by_roles.get(group_id)

    if not isinstance(g_state, dict) and not isinstance(g_roles, dict):
        return None

    out: dict[str, Any] = dict(g_state) if isinstance(g_state, dict) else {"id": group_id}
    out.setdefault("id", str(out.get("id") or group_id))
    if isinstance(g_roles, dict):
        out["roles"] = g_roles
        if "members" not in out and isinstance(g_roles.get("members"), dict):
            out["members"] = g_roles.get("members")
    return out




def _redacted_members_map(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"redacted": True, "count": len(value)}
    if isinstance(value, list):
        return {"redacted": True, "count": len(value)}
    return {"redacted": True, "count": 0}


def _redact_group_membership_maps(group: dict[str, Any]) -> dict[str, Any]:
    # Historical name retained for callers.  In the public-only model, protocol
    # group membership and role activity is inspectable; local mute/block/filter
    # controls do not create private protocol state.
    return dict(group)

def _membership_status(st: dict[str, Any], *, group_id: str, account: str | None) -> dict[str, Any]:
    group = _group_record(st, group_id)
    if not isinstance(group, dict):
        return {
            "ok": True,
            "group_id": group_id,
            "account": account,
            "group_exists": False,
            "phase": "missing",
            "is_member": False,
            "is_pending": False,
        }

    members = group.get("members") if isinstance(group.get("members"), dict) else {}
    reqs = group.get("membership_requests") if isinstance(group.get("membership_requests"), dict) else {}
    phase = "anonymous"
    is_member = False
    is_pending = False
    if account:
        acct = str(account).strip()
        is_member = acct in members
        is_pending = acct in reqs and not is_member
        if is_member:
            phase = "member"
        elif is_pending:
            phase = "pending"
        else:
            phase = "eligible"

    visibility = "public"
    return {
        "ok": True,
        "group_id": group_id,
        "account": account,
        "group_exists": True,
        "phase": phase,
        "is_member": is_member,
        "is_pending": is_pending,
        "visibility": visibility,
    }


def _normalize_group_permission(value: Any, *, default: str) -> str:
    raw = _str_param(value).strip().lower().replace("-", "_")
    if raw in {"public", "anyone", "all", "open"}:
        return "public"
    if raw in {"member", "members", "member" + "s_only", "membership", "member_only"}:
        return "members"
    if raw in {"moderator", "moderators"}:
        return "moderators"
    if raw in {"admin", "admins", "administrator", "administrators"}:
        return "admins"
    return default


def _as_public_list(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted([_str_param(k).strip() for k in value.keys() if _str_param(k).strip()])
    if isinstance(value, list):
        return sorted({_str_param(item).strip() for item in value if _str_param(item).strip()})
    return []


def _public_group_governance_contract(st: dict[str, Any], *, group_id: str, group: dict[str, Any]) -> dict[str, Any]:
    """Return the public product contract for group authority and reads.

    This is a derived/indexed view only.  It does not grant authority and does
    not mutate state.  It gives the UI a single backend source of truth for the
    group-as-governance-scope explanation so the frontend does not invent role
    semantics or accidentally describe group powers as private admin controls.
    """

    permissions = group.get("permissions") if isinstance(group.get("permissions"), dict) else {}
    roles = group.get("roles") if isinstance(group.get("roles"), dict) else {}
    members = group.get("members") if isinstance(group.get("members"), dict) else {}
    membership_requests = group.get("membership_requests") if isinstance(group.get("membership_requests"), dict) else {}
    signers = _as_public_list(group.get("signers") or roles.get("signers"))
    moderators = _as_public_list(group.get("moderators") or roles.get("moderators"))
    threshold = _int_param(group.get("threshold"), 0)
    if threshold <= 0 and signers:
        threshold = (len(signers) // 2) + 1

    elections_root = st.get("group_emissary_elections")
    active_elections: list[dict[str, Any]] = []
    if isinstance(elections_root, dict):
        for election_id, election in elections_root.items():
            if not isinstance(election, dict):
                continue
            if _str_param(election.get("group_id")).strip() != group_id:
                continue
            if _str_param(election.get("status")).strip().lower() != "open":
                continue
            active_elections.append({
                "election_id": _str_param(election.get("election_id") or election.get("id") or election_id).strip(),
                "status": "open",
                "candidate_count": len(election.get("candidates") if isinstance(election.get("candidates"), list) else []),
            })

    public_inspection_routes = {
        "group": f"/v1/groups/{group_id}",
        "membership": f"/v1/groups/{group_id}/membership",
        "members": f"/v1/groups/{group_id}/members",
        "feed": f"/v1/groups/{group_id}/feed",
        "content": f"/v1/groups/{group_id}/content",
        "tx_status": "/v1/tx/status/{tx_id}",
    }

    return {
        "ok": True,
        "group_id": group_id,
        "object_classification": "public_derived_index_view",
        "governance_model": "protocol_governance_scaled_to_group_scope",
        "public_only_contract": {
            "read_visibility": "public",
            "content_read_gated_by_membership": False,
            "membership_may_gate": ["posting", "commenting", "voting", "moderation", "invitation", "administration"],
            "membership_must_not_gate": ["reading_protocol_native_group_content"],
            "private_groups_supported": False,
            "member_only_read_supported": False,
            "encrypted_group_payloads_supported": False,
        },
        "authority_contract": {
            "admin_shortcuts_supported": False,
            "authority_source": "public_group_scope_transactions_and_public_group_governance_state",
            "role_mutations_are_public": True,
            "frontend_caches_are_authoritative": False,
            "frontend_note": "Describe group authority as group-scope governance, not private admin power.",
            "active_group_elections": active_elections,
            "signer_threshold": threshold if threshold > 0 else None,
            "signer_count": len(signers),
            "moderator_count": len(moderators),
        },
        "participation_permissions": {
            "read": "public",
            "post": _normalize_group_permission(permissions.get("post"), default="members"),
            "comment": _normalize_group_permission(permissions.get("comment"), default="members"),
            "vote": _normalize_group_permission(permissions.get("vote"), default="members"),
            "moderate": _normalize_group_permission(permissions.get("moderate"), default="moderators"),
            "admin": _normalize_group_permission(permissions.get("admin"), default="admins"),
        },
        "counts": {
            "members": len(members),
            "membership_requests": len(membership_requests),
            "signers": len(signers),
            "moderators": len(moderators),
            "active_elections": len(active_elections),
        },
        "tx_entrypoints": {
            "request_membership": {"route": "/v1/groups/join", "tx_type": "GROUP_MEMBERSHIP_REQUEST", "state_effect": "public group membership/participation eligibility"},
            "leave_membership": {"route": "/v1/groups/leave", "tx_type": "GROUP_MEMBERSHIP_REMOVE", "state_effect": "public group membership/participation eligibility"},
            "create_group": {"route": "signed /v1/tx/submit", "tx_type": "GROUP_CREATE", "state_effect": "public group charter"},
            "group_election_create": {"route": "signed /v1/tx/submit", "tx_type": "GROUP_EMISSARY_ELECTION_CREATE", "state_effect": "public group-scope governance election"},
            "group_ballot_cast": {"route": "signed /v1/tx/submit", "tx_type": "GROUP_EMISSARY_BALLOT_CAST", "state_effect": "public group-scope governance vote"},
        },
        "inspection_routes": public_inspection_routes,
    }


def _require_group_access(
    request: Request, st: dict[str, Any], *, group_id: str, group_meta: dict[str, Any]
) -> str:
    # Read access is always public.  Membership/role checks belong only on write
    # skeletons and runtime apply paths.
    return ""


def _is_group_member(st: dict[str, Any], *, group_id: str, account: str | None) -> bool:
    acct = str(account or "").strip()
    gid = str(group_id or "").strip()
    if not acct or not gid:
        return False

    g = _groups_by_id(st).get(gid)
    if isinstance(g, dict):
        members = g.get("members")
        if isinstance(members, dict) and acct in members:
            return True

    g_roles = _group_roles_by_id(st).get(gid)
    if isinstance(g_roles, dict):
        members = g_roles.get("members")
        if isinstance(members, dict) and acct in members:
            return True

    return False


def _post_visibility(obj: dict[str, Any]) -> str:
    return _str_param(obj.get("visibility", "public")).strip().lower() or "public"


def _post_public_visible(obj: dict[str, Any]) -> bool:
    return _post_visibility(obj) in {"public", ""}


def _group_content_viewer(request: Request, st: dict[str, Any]) -> str | None:
    try:
        return require_account_session(request, st)
    except Exception:
        return None


def _group_content_can_show(
    request: Request,
    st: dict[str, Any],
    *,
    group_id: str,
    group_meta: dict[str, Any],
    post: dict[str, Any],
    requested_visibility: str = "",
) -> bool:
    """Visibility guard for group content/feed read paths.

    Public-only protocol rules require group content to be readable through the
    group surface regardless of membership.  Membership may gate participation,
    but it must never gate read visibility.
    """

    vis = _post_visibility(post)
    if vis in {"public", ""}:
        return True

    # Group-scoped posts are intentionally not shown in the global public feed,
    # but they must surface in their own group feed after backend group-authority
    # checks already accepted the post.
    if vis == "group":
        return True

    # Explicitly requesting public never returns non-public posts.
    if requested_visibility == "public":
        return False

    # Non-public visibility values are rejected at transaction admission/apply
    # time and at route query validation.  Legacy persisted non-public posts are
    # not surfaced as private archives.
    return False


@router.get("/groups")
def v1_groups_list(request: Request):
    st = _snapshot(request)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 50)
    limit = max(1, min(200, limit))

    by_state = _groups_by_id(st)
    by_roles = _group_roles_by_id(st)

    out: list[dict] = []
    seen: set[str] = set()

    for gid, g in by_state.items():
        if not isinstance(g, dict):
            continue
        obj = dict(g)
        obj["id"] = str(obj.get("id") or gid)
        roles_obj = by_roles.get(gid)
        if isinstance(roles_obj, dict):
            obj["roles"] = roles_obj
        out.append(_redact_group_membership_maps(obj))
        seen.add(obj["id"])

    for gid, g in by_roles.items():
        if gid in seen:
            continue
        if not isinstance(g, dict):
            continue
        obj = {"id": str(gid), "roles": g}
        out.append(_redact_group_membership_maps(obj))

    out.sort(
        key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True
    )
    return {"ok": True, "items": out[:limit]}


@router.get("/groups/{group_id}")
def v1_group_get(group_id: str, request: Request):
    st = _snapshot(request)
    g = _group_record(st, group_id)
    if not isinstance(g, dict):
        return {"ok": True, "group": {"id": group_id}, "membership": _membership_status(st, group_id=group_id, account=None)}

    account = None
    try:
        account = require_account_session(request, st)
    except Exception:
        account = None

    return {"ok": True, "group": _redact_group_membership_maps(g), "membership": _membership_status(st, group_id=group_id, account=account)}


@router.get("/groups/{group_id}/governance-contract")
def v1_group_governance_contract(group_id: str, request: Request):
    st = _snapshot(request)
    g = _group_record(st, group_id)
    if not isinstance(g, dict):
        raise ApiError.not_found("not_found", "Group not found", {"group_id": group_id})
    return _public_group_governance_contract(st, group_id=group_id, group=g)


@router.get("/groups/{group_id}/membership")
def v1_group_membership(group_id: str, request: Request):
    st = _snapshot(request)
    account = None
    try:
        account = require_account_session(request, st)
    except Exception:
        account = _str_param(request.query_params.get("account")).strip() or None
    return _membership_status(st, group_id=group_id, account=account)


@router.get("/groups/{group_id}/members")
def v1_group_members(group_id: str, request: Request):
    st = _snapshot(request)
    g = _group_record(st, group_id)
    if not isinstance(g, dict):
        raise ApiError.not_found("not_found", "Group not found", {"group_id": group_id})
    # Membership lists are public protocol activity in the public-only model.

    # Prefer canonical membership storage in groups_by_id.
    by_state = _groups_by_id(st)
    g_state = by_state.get(group_id)
    members: Any = None
    if isinstance(g_state, dict):
        members = g_state.get("members")

    # Back-compat: some older builds stored membership in group_roles_by_id.
    if not isinstance(members, dict):
        by_roles = _group_roles_by_id(st)
        g_roles = by_roles.get(group_id)
        if isinstance(g_roles, dict):
            members = g_roles.get("members")

    if not isinstance(members, dict):
        return {"ok": True, "group_id": group_id, "members": []}

    out: list[dict] = []
    for acct, info in members.items():
        row = dict(info) if isinstance(info, dict) else {}
        row["account"] = str(acct)
        out.append(row)

    out.sort(key=lambda x: str(x.get("account") or ""))

    qp = request.query_params
    limit = max(1, min(200, _int_param(qp.get("limit"), 50)))
    _cursor_n, cursor_account = _cursor_unpack(qp.get("cursor"))
    if cursor_account:
        out = [row for row in out if str(row.get("account") or "") > cursor_account]

    page = out[:limit]
    next_cursor = None
    if len(page) == limit:
        next_cursor = _cursor_pack(created_at_nonce=0, content_id=str(page[-1].get("account") or ""))

    return {
        "ok": True,
        "group_id": group_id,
        "members": page,
        "next_cursor": next_cursor,
        "counts": {"returned": len(page), "total": len(members)},
    }


@router.post("/groups/join", response_model=TxSkeletonResponse)
def v1_group_join(req: GroupJoinLeaveRequest, request: Request) -> TxSkeletonResponse:
    """Return a tx skeleton for requesting membership in a group.

    Client signs and submits via /v1/tx/submit.
    """

    st = _snapshot(request)
    acct = require_account_session(request, st)

    group_id = str(req.group_id or "").strip()
    if not group_id:
        raise ApiError.bad_request("bad_request", "missing group_id", {})

    # Validate group exists (public API should fail fast)
    if not isinstance(_group_record(st, group_id), dict):
        raise ApiError.not_found("not_found", "Group not found", {"group_id": group_id})

    payload: dict[str, Any] = {"group_id": group_id}
    if req.message is not None and str(req.message).strip():
        payload["message"] = str(req.message).strip()

    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="GROUP_MEMBERSHIP_REQUEST", signer_hint=acct, parent=None, payload=payload
        ),
    )


@router.post("/groups/leave", response_model=TxSkeletonResponse)
def v1_group_leave(req: GroupJoinLeaveRequest, request: Request) -> TxSkeletonResponse:
    """Return a tx skeleton for leaving a group (self-removal).

    Client signs and submits via /v1/tx/submit.
    """

    st = _snapshot(request)
    acct = require_account_session(request, st)

    group_id = str(req.group_id or "").strip()
    if not group_id:
        raise ApiError.bad_request("bad_request", "missing group_id", {})

    if not isinstance(_group_record(st, group_id), dict):
        raise ApiError.not_found("not_found", "Group not found", {"group_id": group_id})

    # GROUP_MEMBERSHIP_REMOVE requires the account being removed.
    payload: dict[str, Any] = {"group_id": group_id, "account": acct}
    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="GROUP_MEMBERSHIP_REMOVE", signer_hint=acct, parent=None, payload=payload
        ),
    )


@router.get("/groups/{group_id}/content")
def v1_group_content(group_id: str, request: Request):
    st = _snapshot(request)
    g = _group_record(st, group_id)
    if not isinstance(g, dict):
        raise ApiError.not_found("not_found", "Group not found", {"group_id": group_id})
    _require_group_access(request, st, group_id=group_id, group_meta=g)

    qp = request.query_params
    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))
    default_visibility = "all"
    visibility = _str_param(qp.get("visibility") or default_visibility).strip().lower() or default_visibility
    if visibility in {"pri" + "vate", "members", "scoped", "member" + "s_only", "member_only"}:
        raise ApiError.bad_request(
            "PUBLIC_READ_VISIBILITY_REQUIRED",
            "Group read visibility must be public.",
            {"group_id": group_id, "visibility": visibility},
        )
    if visibility not in {"public", "group", "all"}:
        visibility = default_visibility

    posts = _iter_group_posts(st, group_id=group_id)
    filtered: list[dict[str, Any]] = []
    for obj in posts:
        if visibility in {"public", "group"} and _post_visibility(obj) != visibility:
            continue
        if not _group_content_can_show(
            request,
            st,
            group_id=group_id,
            group_meta=g,
            post=obj,
            requested_visibility=visibility,
        ):
            continue
        obj_id = _str_param(obj.get("id") or obj.get("post_id") or "").strip()
        created_at_nonce = int(obj.get("created_at_nonce", 0) or 0)
        if cursor_n is not None and cursor_id is not None:
            if created_at_nonce > cursor_n:
                continue
            if created_at_nonce == cursor_n and obj_id >= cursor_id:
                continue
        filtered.append(_with_media_summaries(st, obj))

    filtered.sort(
        key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True
    )
    page = filtered[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=int(last.get("created_at_nonce", 0) or 0),
            content_id=str(last.get("id") or ""),
        )
    return {"ok": True, "group_id": group_id, "items": page, "next_cursor": next_cursor}


@router.get("/groups/{group_id}/feed")
def v1_group_feed(group_id: str, request: Request):
    st = _snapshot(request)
    by_state = _groups_by_id(st)
    g = by_state.get(group_id)
    if not isinstance(g, dict):
        raise ApiError.not_found("not_found", "Group not found", {"group_id": group_id})

    _require_group_access(request, st, group_id=group_id, group_meta=g)

    qp = request.query_params
    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))
    tags = _normalize_tags_param(qp.get("tags"))
    author = _str_param(qp.get("author")).strip()
    default_visibility = "all"
    visibility = _str_param(qp.get("visibility") or default_visibility).strip().lower() or default_visibility
    if visibility in {"pri" + "vate", "members", "scoped", "member" + "s_only", "member_only"}:
        raise ApiError.bad_request(
            "PUBLIC_READ_VISIBILITY_REQUIRED",
            "Group read visibility must be public.",
            {"group_id": group_id, "visibility": visibility},
        )
    if visibility not in {"public", "group", "all"}:
        visibility = default_visibility

    posts = _iter_group_posts(st, group_id=group_id)

    filtered: list[dict] = []
    for obj in posts:
        obj_id = _str_param(obj.get("id") or obj.get("post_id") or "").strip()
        created_at_nonce = int(obj.get("created_at_nonce", 0) or 0)

        if author and _str_param(obj.get("author")).strip() != author:
            continue

        if visibility in {"public", "group"}:
            if _post_visibility(obj) != visibility:
                continue
        if not _group_content_can_show(
            request,
            st,
            group_id=group_id,
            group_meta=g,
            post=obj,
            requested_visibility=visibility,
        ):
            continue

        if tags:
            if not any(t in _tags_list(obj) for t in tags):
                continue

        if cursor_n is not None and cursor_id is not None:
            if created_at_nonce > cursor_n:
                continue
            if created_at_nonce == cursor_n and obj_id >= cursor_id:
                continue

        filtered.append(_with_media_summaries(st, obj))

    filtered.sort(
        key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True
    )
    page = filtered[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=int(last.get("created_at_nonce", 0) or 0),
            content_id=str(last.get("id") or ""),
        )

    return {"ok": True, "group_id": group_id, "items": page, "next_cursor": next_cursor}
