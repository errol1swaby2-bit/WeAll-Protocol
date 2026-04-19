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
    if bool(g.get("is_private", False)):
        return True
    vis = str(g.get("visibility") or g.get("privacy") or "").strip().lower()
    if vis in {"private", "closed", "members"}:
        return True
    meta = g.get("meta")
    if isinstance(meta, dict):
        if bool(meta.get("is_private", False)):
            return True
        vis2 = str(meta.get("visibility") or meta.get("privacy") or "").strip().lower()
        if vis2 in {"private", "closed", "members"}:
            return True
    return False


def _tags_list(obj: dict[str, Any]) -> list[str]:
    raw = obj.get("tags")
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    return []


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
        if bool(obj.get("deleted", False)):
            continue

        row = dict(obj)
        post_id = _str_param(row.get("post_id") or row.get("id") or pid).strip()
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
            phase = "eligible" if not _group_is_private(group) else "not_member"

    visibility = "private" if _group_is_private(group) else "public"
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


def _require_group_access(
    request: Request, st: dict[str, Any], *, group_id: str, group_meta: dict[str, Any]
) -> str:
    if not _group_is_private(group_meta):
        return ""

    try:
        acct = require_account_session(request, st)
    except PermissionError:
        raise ApiError.forbidden("forbidden", "Private group requires login")

    # Canonical membership lives in groups_by_id[*].members. Older builds stored
    # membership under group_roles_by_id[*].members; support both.
    by_state = _groups_by_id(st)
    g = by_state.get(group_id)
    if isinstance(g, dict):
        members = g.get("members")
        if isinstance(members, dict) and acct in members:
            return acct

    roles = _group_roles_by_id(st)
    g_roles = roles.get(group_id)
    if isinstance(g_roles, dict):
        members2 = g_roles.get("members")
        if isinstance(members2, dict) and acct in members2:
            return acct

    raise ApiError.forbidden(
        "forbidden", "Not a group member", {"group_id": group_id, "account": acct}
    )

    return acct


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
        out.append(obj)
        seen.add(obj["id"])

    for gid, g in by_roles.items():
        if gid in seen:
            continue
        if not isinstance(g, dict):
            continue
        obj = {"id": str(gid), "roles": g}
        out.append(obj)

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

    return {"ok": True, "group": g, "membership": _membership_status(st, group_id=group_id, account=account)}


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
    return {"ok": True, "group_id": group_id, "members": out}


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
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))

    posts = _iter_group_posts(st, group_id=group_id)
    posts.sort(
        key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True
    )
    return {"ok": True, "group_id": group_id, "items": posts[:limit]}


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
    visibility = _str_param(qp.get("visibility")).strip().lower()

    if visibility == "private":
        try:
            require_account_session(request, st)
        except PermissionError:
            raise ApiError.forbidden("forbidden", "Private group feed requires login")

    posts = _iter_group_posts(st, group_id=group_id)

    filtered: list[dict] = []
    for obj in posts:
        obj_id = _str_param(obj.get("id") or obj.get("post_id") or "").strip()
        created_at_nonce = int(obj.get("created_at_nonce", 0) or 0)

        if author and _str_param(obj.get("author")).strip() != author:
            continue

        if visibility in {"public", "private"}:
            if _str_param(obj.get("visibility", "public")).strip().lower() != visibility:
                continue

        if tags:
            if not any(t in _tags_list(obj) for t in tags):
                continue

        if cursor_n is not None and cursor_id is not None:
            if created_at_nonce > cursor_n:
                continue
            if created_at_nonce == cursor_n and obj_id >= cursor_id:
                continue

        filtered.append(obj)

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
