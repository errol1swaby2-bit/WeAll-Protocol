from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import (
    _cursor_pack,
    _cursor_unpack,
    _int_param,
    _group_roles_by_id,
    _groups_by_id,
    _normalize_tags_param,
    _str_param,
)
from weall.api.security import require_account_session

router = APIRouter()

Json = dict[str, Any]


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _snapshot(request: Request) -> Json:
    ex = getattr(request.app.state, "executor", None)
    if ex is None:
        return {}

    if hasattr(ex, "read_state"):
        try:
            st = ex.read_state()
            return st if isinstance(st, dict) else {}
        except Exception:
            return {}

    try:
        st = ex.snapshot()
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def _content_root(st: Json) -> Json:
    return _as_dict(st.get("content"))


def _posts(st: Json) -> Json:
    return _as_dict(_content_root(st).get("posts"))


def _comments(st: Json) -> Json:
    return _as_dict(_content_root(st).get("comments"))


def _moderation_targets(st: Json) -> Json:
    content = _content_root(st)
    moderation = _as_dict(content.get("moderation"))
    return _as_dict(moderation.get("targets"))


def _post_visible(post: Json) -> bool:
    if not isinstance(post, dict):
        return False
    if bool(post.get("deleted", False)):
        return False
    # Conservative default: only return public posts on the public feed.
    vis = str(post.get("visibility", "public") or "public").strip().lower()
    return vis in {"public", ""}


def _comment_visible(st: Json, comment: Json) -> bool:
    if not isinstance(comment, dict):
        return False
    if bool(comment.get("deleted", False)):
        return False
    vis = str(comment.get("visibility", "public") or "public").strip().lower()
    if vis not in {"public", ""}:
        return False
    root_id = str(comment.get("post_id") or comment.get("thread_id") or "").strip()
    if not root_id:
        return True
    root = _as_dict(_posts(st).get(root_id))
    return bool(root and _post_visible(root))



def _tags_list(obj: Json) -> list[str]:
    raw = obj.get("tags")
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    return []


def _media_root(st: Json) -> Json:
    return _as_dict(_content_root(st).get("media"))


def _media_ref_summary(raw: Any, media_index: Json) -> Any:
    """Return metadata-only media references for feed responses.

    This deliberately never fetches blobs. It only translates committed media ids
    into bounded display metadata so observer/frontends can stay metadata-first
    until viewport-triggered media loading asks the local observer for the CID.
    """
    if isinstance(raw, str):
        media_id = raw.strip()
        rec = _as_dict(media_index.get(media_id)) if media_id else {}
        if not rec:
            return raw
        payload = _as_dict(rec.get("payload"))
        cid = str(rec.get("cid") or payload.get("cid") or payload.get("upload_ref") or "").strip()
        out: Json = {
            "media_id": media_id,
            "cid": cid,
            "mime": str(payload.get("mime") or payload.get("mime_type") or payload.get("content_type") or "").strip(),
            "name": str(payload.get("name") or payload.get("filename") or media_id).strip(),
            "kind": str(rec.get("kind") or payload.get("kind") or "").strip(),
            "bytes": _safe_int(payload.get("size") or payload.get("size_bytes"), 0),
            "declared_by": str(rec.get("declared_by") or "").strip(),
            "declared_at_nonce": rec.get("declared_at_nonce"),
            "load_policy": "viewport",
            "fetch_path": f"/v1/media/proxy/{cid}" if cid else "",
        }
        return out

    if isinstance(raw, dict):
        cid = str(raw.get("cid") or raw.get("upload_ref") or raw.get("ref") or "").strip()
        out = dict(raw)
        out.setdefault("load_policy", "viewport")
        if cid:
            out.setdefault("fetch_path", f"/v1/media/proxy/{cid}")
        return out

    return raw


def _with_media_summaries(st: Json, obj: Json) -> Json:
    out = dict(obj)
    raw_media = _as_list(out.get("media"))
    if not raw_media:
        return out
    media_index = _media_root(st)
    out["media"] = [_media_ref_summary(item, media_index) for item in raw_media]
    out["media_load_policy"] = "viewport"
    return out



def _group_is_private_record(g: Json) -> bool:
    if not isinstance(g, dict):
        return False
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


def _group_record_for_content(st: Json, group_id: str) -> Json:
    gid = str(group_id or "").strip()
    if not gid:
        return {}
    by_state = _groups_by_id(st)
    by_roles = _group_roles_by_id(st)
    g_state = by_state.get(gid)
    g_roles = by_roles.get(gid)
    if not isinstance(g_state, dict) and not isinstance(g_roles, dict):
        return {}
    out: Json = dict(g_state) if isinstance(g_state, dict) else {"id": gid, "group_id": gid}
    if isinstance(g_roles, dict):
        out.setdefault("roles", g_roles)
        if "members" not in out and isinstance(g_roles.get("members"), dict):
            out["members"] = g_roles.get("members")
    return out


def _is_group_member(st: Json, *, group_id: str, account: str) -> bool:
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


def _owner_of_content(obj: Json) -> str:
    return str(
        obj.get("author")
        or obj.get("owner")
        or obj.get("account_id")
        or obj.get("created_by")
        or obj.get("signer")
        or ""
    ).strip()


def _visibility_of_content(obj: Json) -> str:
    return str(obj.get("visibility", "public") or "public").strip().lower()


def _group_id_of_content(obj: Json) -> str:
    return str(obj.get("group_id") or obj.get("group") or "").strip()


def _viewer_can_read_post(st: Json, post: Json, viewer: str) -> bool:
    if not isinstance(post, dict) or bool(post.get("deleted", False)):
        return False

    vis = _visibility_of_content(post)
    owner = _owner_of_content(post)
    gid = _group_id_of_content(post)

    if vis in {"public", ""} and not gid:
        return True

    if owner and owner == viewer:
        return True

    if gid:
        g = _group_record_for_content(st, gid)
        if not g:
            return False
        if _group_is_private_record(g):
            return _is_group_member(st, group_id=gid, account=viewer)
        # Public group content remains readable to everyone unless the post has
        # an explicitly private/non-public visibility. The scoped route is more
        # permissive for authenticated users, not a replacement for public feed.
        if vis in {"public", ""}:
            return True
        return _is_group_member(st, group_id=gid, account=viewer)

    if vis in {"private", "direct", "owner", "members", "hidden", "unlisted"}:
        return bool(owner and owner == viewer)

    return False


def _viewer_can_read_comment(st: Json, comment: Json, viewer: str) -> bool:
    if not isinstance(comment, dict) or bool(comment.get("deleted", False)):
        return False
    owner = _owner_of_content(comment)
    if owner and owner == viewer:
        return True
    root_id = str(comment.get("post_id") or comment.get("thread_id") or "").strip()
    root = _as_dict(_posts(st).get(root_id)) if root_id else {}
    if root:
        return _viewer_can_read_post(st, root, viewer)
    return _visibility_of_content(comment) in {"public", ""}

def _sort_by_nonce_desc(items: list[Json], *, key: str) -> list[Json]:
    def k(obj: Json) -> tuple[int, str]:
        return (_safe_int(obj.get(key), 0), str(obj.get("post_id") or obj.get("comment_id") or ""))

    return sorted(items, key=k, reverse=True)


def _reaction_counts_by_target(st: Json) -> dict[str, dict[str, int]]:
    content = _content_root(st)
    reactions = _as_dict(content.get("reactions"))
    counts: dict[str, dict[str, int]] = {}
    for _, raw in sorted(reactions.items(), key=lambda item: str(item[0])):
        rec = _as_dict(raw)
        target_id = str(rec.get("target_id") or "").strip()
        reaction = str(rec.get("reaction") or "").strip().lower()
        if not target_id or not reaction:
            continue
        target_counts = counts.setdefault(target_id, {})
        target_counts[reaction] = int(target_counts.get(reaction, 0)) + 1
    return counts


def _with_reaction_counts(obj: Json, counts_by_target: dict[str, dict[str, int]]) -> Json:
    out = dict(obj)
    target_id = str(out.get("comment_id") or out.get("post_id") or out.get("content_id") or "").strip()
    existing = _as_dict(out.get("reactions"))
    merged: Json = {}
    for key, value in existing.items():
        if isinstance(value, (int, float)):
            merged[str(key)] = int(value)
    if target_id and target_id in counts_by_target:
        for reaction, count in counts_by_target[target_id].items():
            merged[str(reaction)] = int(count)
    out["reactions"] = merged
    out["reaction_total"] = int(sum(int(v) for v in merged.values())) if merged else 0
    return out


@router.get("/feed")
def feed(request: Request) -> dict[str, object]:
    """Public feed.

    Production read-path rules:
      - returns non-deleted, visible posts only
      - supports bounded pagination instead of returning the full history
      - returns metadata-only media summaries; media blobs are never fetched here
      - sorted by created nonce descending

    This keeps observer/frontends metadata-first. Viewport-triggered media loads
    should use the local observer media proxy only when a media card approaches
    the user's viewport.
    """

    st = _snapshot(request)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))
    visibility = _str_param(qp.get("visibility"), "public").strip().lower() or "public"
    tags = _normalize_tags_param(qp.get("tags"))
    author = _str_param(qp.get("author")).strip()

    posts = _posts(st)
    reaction_counts = _reaction_counts_by_target(st)

    filtered: list[Json] = []
    for pid, p in posts.items():
        post = _with_reaction_counts(_as_dict(p), reaction_counts)
        post_id = _str_param(post.get("post_id") or post.get("id") or pid).strip()
        post.setdefault("id", post_id)
        post.setdefault("created_at_nonce", _safe_int(post.get("created_nonce"), 0))
        created_at_nonce = _safe_int(post.get("created_at_nonce") or post.get("created_nonce"), 0)

        if not _post_visible(post):
            continue

        if visibility in {"public", "private"}:
            if _str_param(post.get("visibility"), "public").strip().lower() != visibility:
                continue
        elif visibility != "all":
            # Unknown visibility filters fail closed to public.
            if _str_param(post.get("visibility"), "public").strip().lower() != "public":
                continue

        if author and _str_param(post.get("author")).strip() != author:
            continue

        if tags and not any(t in _tags_list(post) for t in tags):
            continue

        if cursor_n is not None and cursor_id is not None:
            if created_at_nonce > cursor_n:
                continue
            if created_at_nonce == cursor_n and post_id >= cursor_id:
                continue

        filtered.append(_with_media_summaries(st, post))

    filtered = _sort_by_nonce_desc(filtered, key="created_at_nonce")
    page = filtered[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=_safe_int(last.get("created_at_nonce") or last.get("created_nonce"), 0),
            content_id=str(last.get("id") or last.get("post_id") or ""),
        )

    return {"ok": True, "items": page, "next_cursor": next_cursor}


@router.get("/content/{content_id}")
def content_get(request: Request, content_id: str) -> dict[str, object]:
    """Get a single content object.

    Lookup order:
      1) posts[content_id]
      2) comments[content_id]

    Returns 404 if not found.
    """

    st = _snapshot(request)

    pid = str(content_id or "").strip()
    if not pid:
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "content not found"}
        )

    moderation = _moderation_targets(st)

    posts = _posts(st)
    if pid in posts:
        post = _with_reaction_counts(_as_dict(posts.get(pid)), _reaction_counts_by_target(st))
        if bool(post.get("deleted", False)) or not _post_visible(post):
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "content not found"}
            )
        return {
            "ok": True,
            "type": "post",
            "content": _with_media_summaries(st, post),
            "moderation": _as_dict(moderation.get(pid)),
        }

    comments = _comments(st)
    if pid in comments:
        com = _with_reaction_counts(_as_dict(comments.get(pid)), _reaction_counts_by_target(st))
        if bool(com.get("deleted", False)) or not _comment_visible(st, com):
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "content not found"}
            )
        return {
            "ok": True,
            "type": "comment",
            "content": _with_media_summaries(st, com),
            "moderation": _as_dict(moderation.get(pid)),
        }

    raise HTTPException(
        status_code=404, detail={"code": "not_found", "message": "content not found"}
    )


@router.get("/content/{content_id}/scoped")
def content_get_scoped(request: Request, content_id: str) -> dict[str, object]:
    """Get a content object through an authenticated, scoped read path.

    Public /v1/content/{id} remains fail-closed for non-public content. This
    route lets authorized viewers read private/group content without reopening
    broad state snapshots or leaking content by id to anonymous callers.
    """

    st = _snapshot(request)
    try:
        viewer = require_account_session(request, st)
    except PermissionError as exc:
        code = str(exc) or "session_missing"
        raise ApiError.forbidden(code, code.replace("_", " "), {})

    pid = str(content_id or "").strip()
    if not pid:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})

    moderation = _moderation_targets(st)
    reaction_counts = _reaction_counts_by_target(st)

    posts = _posts(st)
    if pid in posts:
        post = _with_reaction_counts(_as_dict(posts.get(pid)), reaction_counts)
        if not _viewer_can_read_post(st, post, viewer):
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})
        return {
            "ok": True,
            "type": "post",
            "content": _with_media_summaries(st, post),
            "moderation": _as_dict(moderation.get(pid)),
            "scope": {"viewer": viewer, "authorized": True},
        }

    comments = _comments(st)
    if pid in comments:
        com = _with_reaction_counts(_as_dict(comments.get(pid)), reaction_counts)
        if not _viewer_can_read_comment(st, com, viewer):
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})
        return {
            "ok": True,
            "type": "comment",
            "content": _with_media_summaries(st, com),
            "moderation": _as_dict(moderation.get(pid)),
            "scope": {"viewer": viewer, "authorized": True},
        }

    raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})


@router.get("/thread/{thread_id}")
def thread_get(request: Request, thread_id: str) -> dict[str, object]:
    """Thread view: root post + its comments.

    The frontend expects this endpoint.
    """

    st = _snapshot(request)
    tid = str(thread_id or "").strip()

    posts = _posts(st)
    reaction_counts = _reaction_counts_by_target(st)
    root = _with_reaction_counts(_as_dict(posts.get(tid)), reaction_counts)
    if not root or bool(root.get("deleted", False)):
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "thread not found"}
        )

    # Public endpoint: hide non-public roots.
    if not _post_visible(root):
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "thread not found"}
        )

    qp = request.query_params
    limit = max(1, min(200, _int_param(qp.get("limit"), 50)))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))

    comments = _comments(st)
    all_comments: list[Json] = []
    for cid, c in comments.items():
        com = _with_reaction_counts(_as_dict(c), reaction_counts)
        if bool(com.get("deleted", False)):
            continue
        if str(com.get("post_id") or "") != tid:
            continue
        if not _comment_visible(st, com):
            continue
        comment_id = _str_param(com.get("comment_id") or com.get("id") or cid).strip()
        com.setdefault("comment_id", comment_id)
        com.setdefault("id", comment_id)
        created_nonce = _safe_int(com.get("created_nonce") or com.get("created_at_nonce"), 0)
        com.setdefault("created_at_nonce", created_nonce)
        if cursor_n is not None and cursor_id is not None:
            if created_nonce > cursor_n:
                continue
            if created_nonce == cursor_n and comment_id >= cursor_id:
                continue
        all_comments.append(_with_media_summaries(st, com))

    out_comments = _sort_by_nonce_desc(all_comments, key="created_at_nonce")
    page = out_comments[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=_safe_int(last.get("created_at_nonce") or last.get("created_nonce"), 0),
            content_id=str(last.get("comment_id") or last.get("id") or ""),
        )

    return {
        "ok": True,
        "post": _with_media_summaries(st, root),
        "comments": page,
        "next_cursor": next_cursor,
        "counts": {"comments": len(out_comments), "returned": len(page)},
    }
