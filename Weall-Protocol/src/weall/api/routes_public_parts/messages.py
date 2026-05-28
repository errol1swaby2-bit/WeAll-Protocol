from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from weall.api.routes_public_parts.common import _cursor_pack, _cursor_unpack, _int_param, _snapshot
from weall.api.security import require_account_session

router = APIRouter()

Json = dict[str, Any]


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _require_viewer(request: Request, st: Json) -> str:
    try:
        return require_account_session(request, st)
    except PermissionError as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": str(exc) or "session_invalid", "message": "valid account session required"},
        ) from exc


def _messaging_root(st: Json) -> Json:
    return _as_dict(st.get("messaging"))


def _threads_by_id(st: Json) -> Json:
    return _as_dict(_messaging_root(st).get("threads_by_id"))


def _messages_by_id(st: Json) -> Json:
    return _as_dict(_messaging_root(st).get("messages_by_id"))


def _inbox_for(st: Json, account: str) -> Json:
    inboxes = _as_dict(_messaging_root(st).get("inbox_by_account"))
    return _as_dict(inboxes.get(account))


def _member_of(thread: Json, viewer: str) -> bool:
    return viewer in [str(m).strip() for m in _as_list(thread.get("members"))]


def _message_summary(raw: Any, *, viewer: str) -> Json:
    rec = _as_dict(raw)
    sender = str(rec.get("sender") or "").strip()
    to = str(rec.get("to") or rec.get("recipient") or "").strip()
    if viewer not in {sender, to}:
        return {}
    redacted = bool(rec.get("redacted", False))
    body = "" if redacted else str(rec.get("body") or "")
    cid = "" if redacted else str(rec.get("cid") or "").strip()
    encryption = _as_dict(rec.get("encryption")) if not redacted else {}
    out: Json = {
        "message_id": str(rec.get("message_id") or rec.get("id") or "").strip(),
        "thread_id": str(rec.get("thread_id") or "").strip(),
        "sender": sender,
        "to": to,
        "body": body,
        "cid": cid,
        "encrypted": bool(rec.get("encrypted", False)) and not redacted,
        "encryption": encryption,
        "created_at_nonce": _safe_int(rec.get("created_at_nonce"), 0),
        "redacted": redacted,
    }
    if redacted:
        out["redacted_at_nonce"] = _safe_int(rec.get("redacted_at_nonce"), 0)
    return out


def _thread_summary(raw: Any, *, viewer: str, messages: Json) -> Json:
    thread = _as_dict(raw)
    if not _member_of(thread, viewer):
        return {}
    thread_id = str(thread.get("thread_id") or thread.get("id") or "").strip()
    members = sorted(
        set(str(m).strip() for m in _as_list(thread.get("members")) if str(m).strip())
    )
    raw_message_ids = [str(m).strip() for m in _as_list(thread.get("message_ids")) if str(m).strip()]
    last_message_id = str(thread.get("last_message_id") or (raw_message_ids[-1] if raw_message_ids else "")).strip()
    last_message = _message_summary(messages.get(last_message_id), viewer=viewer) if last_message_id else {}
    return {
        "thread_id": thread_id,
        "members": members,
        "created_at_nonce": _safe_int(thread.get("created_at_nonce"), 0),
        "last_message_at_nonce": _safe_int(thread.get("last_message_at_nonce"), 0),
        "last_message_id": last_message_id,
        "message_count": len(raw_message_ids),
        "last_message": last_message,
    }


def _sort_threads(items: list[Json]) -> list[Json]:
    return sorted(
        items,
        key=lambda t: (_safe_int(t.get("last_message_at_nonce"), 0), str(t.get("thread_id") or "")),
        reverse=True,
    )


def _sort_messages(items: list[Json]) -> list[Json]:
    return sorted(
        items,
        key=lambda m: (_safe_int(m.get("created_at_nonce"), 0), str(m.get("message_id") or "")),
    )


@router.get("/messages/threads")
def message_threads(request: Request) -> Json:
    """Return the authenticated viewer's bounded direct-message thread list.

    This replaces frontend use of the broad public state snapshot. It returns
    only threads where the caller is a member, with at most one last-message
    preview per thread.
    """

    st = _snapshot(request)
    viewer = _require_viewer(request, st)
    qp = request.query_params
    limit = max(1, min(100, _int_param(qp.get("limit"), 25)))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))

    threads_by_id = _threads_by_id(st)
    messages = _messages_by_id(st)
    inbox = _inbox_for(st, viewer)
    inbox_thread_ids = [str(t).strip() for t in _as_list(inbox.get("threads")) if str(t).strip()]

    # Batch 451: treat the inbox index as a cache, not the authority.
    # Observer/downstream sync can briefly contain the thread/message record before
    # the convenience inbox index is visible on the same read model.  A normal
    # user should still see conversations where the thread membership includes
    # them; otherwise the detail page can show a message while the hub says
    # "0 chats".
    membership_thread_ids = [
        str(tid).strip()
        for tid, thread in threads_by_id.items()
        if str(tid).strip() and _member_of(_as_dict(thread), viewer)
    ]
    candidate_thread_ids = sorted(set(inbox_thread_ids + membership_thread_ids))

    out: list[Json] = []
    for thread_id in candidate_thread_ids:
        summary = _thread_summary(threads_by_id.get(thread_id), viewer=viewer, messages=messages)
        if not summary:
            continue
        last_nonce = _safe_int(summary.get("last_message_at_nonce"), 0)
        sid = str(summary.get("thread_id") or "")
        if cursor_n is not None and cursor_id is not None:
            if last_nonce > cursor_n:
                continue
            if last_nonce == cursor_n and sid >= cursor_id:
                continue
        out.append(summary)

    out = _sort_threads(out)
    page = out[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=_safe_int(last.get("last_message_at_nonce"), 0),
            content_id=str(last.get("thread_id") or ""),
        )

    return {"ok": True, "account": viewer, "threads": page, "next_cursor": next_cursor}


@router.get("/messages/threads/{thread_id:path}")
def message_thread(request: Request, thread_id: str) -> Json:
    """Return one authenticated direct-message thread with bounded messages."""

    st = _snapshot(request)
    viewer = _require_viewer(request, st)
    tid = str(thread_id or "").strip()
    if not tid:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "thread not found"})

    threads = _threads_by_id(st)
    messages = _messages_by_id(st)
    thread = _as_dict(threads.get(tid))
    if not thread or not _member_of(thread, viewer):
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "thread not found"})

    qp = request.query_params
    limit = max(1, min(200, _int_param(qp.get("limit"), 50)))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))
    message_ids = [str(m).strip() for m in _as_list(thread.get("message_ids")) if str(m).strip()]

    out_messages: list[Json] = []
    for mid in message_ids:
        msg = _message_summary(messages.get(mid), viewer=viewer)
        if not msg:
            continue
        created = _safe_int(msg.get("created_at_nonce"), 0)
        if cursor_n is not None and cursor_id is not None:
            if created < cursor_n:
                continue
            if created == cursor_n and str(msg.get("message_id") or "") <= cursor_id:
                continue
        out_messages.append(msg)

    out_messages = _sort_messages(out_messages)
    page = out_messages[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=_safe_int(last.get("created_at_nonce"), 0),
            content_id=str(last.get("message_id") or ""),
        )

    summary = _thread_summary(thread, viewer=viewer, messages=messages)
    return {
        "ok": True,
        "account": viewer,
        "thread": summary,
        "messages": page,
        "next_cursor": next_cursor,
        "counts": {"messages": len(message_ids), "returned": len(page)},
    }
