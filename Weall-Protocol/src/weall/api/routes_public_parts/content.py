from __future__ import annotations

from typing import Any, Dict, List, Tuple

from fastapi import APIRouter, HTTPException, Request


router = APIRouter()

Json = Dict[str, Any]


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _snapshot(request: Request) -> Json:
    ex = getattr(request.app.state, "executor", None)
    if ex is None:
        raise HTTPException(status_code=503, detail={"code": "not_ready", "message": "executor not ready"})
    st = ex.snapshot()
    return st if isinstance(st, dict) else {}


def _content_root(st: Json) -> Json:
    return _as_dict(st.get("content"))


def _posts(st: Json) -> Json:
    return _as_dict(_content_root(st).get("posts"))


def _comments(st: Json) -> Json:
    return _as_dict(_content_root(st).get("comments"))


def _post_visible(post: Json) -> bool:
    if not isinstance(post, dict):
        return False
    if bool(post.get("deleted", False)):
        return False
    # Conservative default: only return public posts on the public feed.
    vis = str(post.get("visibility", "public") or "public").strip().lower()
    return vis in {"public", ""}


def _sort_by_nonce_desc(items: List[Json], *, key: str) -> List[Json]:
    def k(obj: Json) -> Tuple[int, str]:
        return (_safe_int(obj.get(key), 0), str(obj.get("post_id") or obj.get("comment_id") or ""))

    return sorted(items, key=k, reverse=True)


@router.get("/feed")
def feed(request: Request) -> dict[str, object]:
    """Public feed.

    This is intentionally simple and deterministic:
      - returns non-deleted, public posts only
      - sorted by created_nonce descending

    NOTE: In later phases you can replace this with the subgraph/AI ranking path.
    """

    st = _snapshot(request)
    posts = _posts(st)

    out: List[Json] = []
    for _pid, p in posts.items():
        post = _as_dict(p)
        if not _post_visible(post):
            continue
        out.append(post)

    out = _sort_by_nonce_desc(out, key="created_nonce")

    # Keep payload stable for the frontend.
    return {"ok": True, "items": out}


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
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})

    posts = _posts(st)
    if pid in posts:
        post = _as_dict(posts.get(pid))
        if bool(post.get("deleted", False)):
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})
        return {"ok": True, "type": "post", "content": post}

    comments = _comments(st)
    if pid in comments:
        com = _as_dict(comments.get(pid))
        if bool(com.get("deleted", False)):
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})
        return {"ok": True, "type": "comment", "content": com}

    raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})


@router.get("/thread/{thread_id}")
def thread_get(request: Request, thread_id: str) -> dict[str, object]:
    """Thread view: root post + its comments.

    The frontend expects this endpoint.
    """

    st = _snapshot(request)
    tid = str(thread_id or "").strip()

    posts = _posts(st)
    root = _as_dict(posts.get(tid))
    if not root or bool(root.get("deleted", False)):
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "thread not found"})

    # Public endpoint: hide non-public roots.
    if not _post_visible(root):
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "thread not found"})

    comments = _comments(st)
    out_comments: List[Json] = []
    for _cid, c in comments.items():
        com = _as_dict(c)
        if bool(com.get("deleted", False)):
            continue
        if str(com.get("post_id") or "") != tid:
            continue
        out_comments.append(com)

    out_comments = _sort_by_nonce_desc(out_comments, key="created_nonce")

    return {
        "ok": True,
        "post": root,
        "comments": out_comments,
        "counts": {"comments": len(out_comments)},
    }
