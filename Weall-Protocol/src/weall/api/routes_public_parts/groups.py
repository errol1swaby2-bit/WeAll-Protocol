# src/weall/api/routes_public_parts/groups.py
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.security import require_account_session

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

router = APIRouter()


def _group_is_private(g: Dict[str, Any]) -> bool:
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


def _tags_list(obj: Dict[str, Any]) -> List[str]:
    raw = obj.get("tags")
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    return []


def _iter_group_posts(st: Dict[str, Any], *, group_id: str) -> List[Dict[str, Any]]:
    content = st.get("content")
    if not isinstance(content, dict):
        return []
    posts = content.get("posts")
    if not isinstance(posts, dict):
        return []

    out: List[Dict[str, Any]] = []
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


def _require_group_access(request: Request, st: Dict[str, Any], *, group_id: str, group_meta: Dict[str, Any]) -> str:
    if not _group_is_private(group_meta):
        return ""

    try:
        acct = require_account_session(request, st)
    except PermissionError:
        raise ApiError.forbidden("forbidden", "Private group requires login")

    roles = _group_roles_by_id(st)
    g_roles = roles.get(group_id)
    if not isinstance(g_roles, dict):
        raise ApiError.forbidden("forbidden", "Private group membership required")
    members = g_roles.get("members")
    if not isinstance(members, dict) or acct not in members:
        raise ApiError.forbidden("forbidden", "Not a group member", {"group_id": group_id, "account": acct})

    return acct


@router.get("/v1/groups")
def v1_groups_list(request: Request):
    st = _snapshot(request)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 50)
    limit = max(1, min(200, limit))

    by_state = _groups_by_id(st)
    by_roles = _group_roles_by_id(st)

    out: List[dict] = []
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

    out.sort(key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True)
    return {"ok": True, "items": out[:limit]}


@router.get("/v1/groups/{group_id}")
def v1_group_get(group_id: str, request: Request):
    st = _snapshot(request)
    by_state = _groups_by_id(st)
    by_roles = _group_roles_by_id(st)

    g = by_state.get(group_id)
    if not isinstance(g, dict):
        g = {"id": group_id}

    roles = by_roles.get(group_id)
    if isinstance(roles, dict):
        g = dict(g)
        g["roles"] = roles

    return {"ok": True, "group": g}


@router.get("/v1/groups/{group_id}/members")
def v1_group_members(group_id: str, request: Request):
    st = _snapshot(request)
    by_roles = _group_roles_by_id(st)

    g = by_roles.get(group_id)
    if not isinstance(g, dict):
        return {"ok": True, "group_id": group_id, "members": []}

    members = g.get("members")
    if not isinstance(members, dict):
        return {"ok": True, "group_id": group_id, "members": []}

    out: List[dict] = []
    for acct, info in members.items():
        row = dict(info) if isinstance(info, dict) else {}
        row["account"] = str(acct)
        out.append(row)

    out.sort(key=lambda x: str(x.get("account") or ""))
    return {"ok": True, "group_id": group_id, "members": out}


@router.get("/v1/groups/{group_id}/content")
def v1_group_content(group_id: str, request: Request):
    st = _snapshot(request)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))

    posts = _iter_group_posts(st, group_id=group_id)
    posts.sort(key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True)
    return {"ok": True, "group_id": group_id, "items": posts[:limit]}


@router.get("/v1/groups/{group_id}/feed")
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

    filtered: List[dict] = []
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

    filtered.sort(key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True)
    page = filtered[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=int(last.get("created_at_nonce", 0) or 0),
            content_id=str(last.get("id") or ""),
        )

    return {"ok": True, "group_id": group_id, "items": page, "next_cursor": next_cursor}
