from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

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


def _post_visible(post: Json) -> bool:
    if not isinstance(post, dict):
        return False
    if bool(post.get("deleted", False)):
        return False
    # Conservative default: only return public posts on the public feed.
    vis = str(post.get("visibility", "public") or "public").strip().lower()
    return vis in {"public", ""}


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
    target_id = str(out.get("post_id") or out.get("comment_id") or out.get("content_id") or "").strip()
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

    This is intentionally simple and deterministic:
      - returns non-deleted, public posts only
      - sorted by created_nonce descending

    NOTE: In later phases you can replace this with the subgraph/AI ranking path.
    """

    st = _snapshot(request)
    posts = _posts(st)
    reaction_counts = _reaction_counts_by_target(st)

    out: list[Json] = []
    for _pid, p in posts.items():
        post = _with_reaction_counts(_as_dict(p), reaction_counts)
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
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "content not found"}
        )

    posts = _posts(st)
    if pid in posts:
        post = _with_reaction_counts(_as_dict(posts.get(pid)), _reaction_counts_by_target(st))
        if bool(post.get("deleted", False)):
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "content not found"}
            )
        return {"ok": True, "type": "post", "content": post}

    comments = _comments(st)
    if pid in comments:
        com = _with_reaction_counts(_as_dict(comments.get(pid)), _reaction_counts_by_target(st))
        if bool(com.get("deleted", False)):
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "content not found"}
            )
        return {"ok": True, "type": "comment", "content": com}

    raise HTTPException(
        status_code=404, detail={"code": "not_found", "message": "content not found"}
    )


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

    comments = _comments(st)
    out_comments: list[Json] = []
    for _cid, c in comments.items():
        com = _with_reaction_counts(_as_dict(c), reaction_counts)
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
