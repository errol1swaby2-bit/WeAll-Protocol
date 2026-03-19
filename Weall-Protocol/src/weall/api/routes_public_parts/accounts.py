from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import (
    _cursor_pack,
    _cursor_unpack,
    _int_param,
    _snapshot,
    _str_param,
)
from weall.api.security import require_account_session
from weall.ledger.state import LedgerView

router = APIRouter()


def _iter_posts_by_author(st: dict[str, Any], *, author: str) -> list[dict[str, Any]]:
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
        if _str_param(obj.get("author")).strip() != author:
            continue

        row = dict(obj)
        post_id = _str_param(row.get("post_id") or row.get("id") or pid).strip()
        row.setdefault("id", post_id)
        row.setdefault("created_at_nonce", int(row.get("created_nonce", 0) or 0))
        row.setdefault("visibility", "public")
        out.append(row)

    return out


def _normalize_keys(acct: dict[str, Any]) -> list[dict]:
    ks = acct.get("keys")
    out: list[dict] = []

    if isinstance(ks, dict):
        for pubkey, rec in ks.items():
            p = str(pubkey or "").strip()
            if not p:
                continue
            active = bool(rec.get("active", True)) if isinstance(rec, dict) else bool(rec)
            out.append({"pubkey": p, "active": active})
        out.sort(key=lambda x: x.get("pubkey", ""))
        return out

    if isinstance(ks, list):
        for it in ks:
            p = str(it or "").strip()
            if p:
                out.append({"pubkey": p, "active": True})
        out.sort(key=lambda x: x.get("pubkey", ""))
        return out

    return out


@router.get("/accounts/{account}")
def v1_account_get(account: str, request: Request):
    """Get the canonical on-chain account state.

    Mounted under /v1 by routes_public.py:
      GET /v1/accounts/{account}
    """

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)
    a = ledger.accounts.get(account)
    return {
        "ok": True,
        "account": account,
        "state": a
        or {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "reputation": 0},
    }


@router.get("/accounts/{account}/registered")
def v1_account_registered(account: str, request: Request):
    """Return whether an account is "registered" for content posting.

    Node eligibility rule:
      - Account exists
      - PoH tier >= 3
      - Not banned

    Mounted under /v1:
      GET /v1/accounts/{account}/registered
    """

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)

    acct = ledger.accounts.get(account)
    if not acct:
        return {"ok": True, "account": account, "registered": False}

    tier = int(acct.get("poh_tier", 0) or 0)
    banned = bool(acct.get("banned", False))

    registered = tier >= 3 and not banned

    return {"ok": True, "account": account, "registered": registered}


@router.get("/accounts/{account}/feed")
def v1_account_feed(account: str, request: Request):
    """List posts authored by `account`.

    Mounted under /v1:
      GET /v1/accounts/{account}/feed

    Query params:
      - limit (default 25, max 100)
      - cursor (pagination)
      - visibility: public|private|all (default public)

    Privacy model (MVP, conservative):
      - public: anyone can view
      - private: only the author may view (requires session matching `account`)
      - all: treated as public unless author session matches; then returns public+private
    """

    st = _snapshot(request)
    qp = request.query_params

    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))
    visibility = _str_param(qp.get("visibility"), "public").strip().lower()

    # Determine whether caller is the account owner.
    viewer = ""
    try:
        viewer = require_account_session(request, st)
    except PermissionError:
        viewer = ""

    is_owner = bool(viewer) and viewer == account

    if visibility == "private" and not is_owner:
        raise ApiError.forbidden("forbidden", "Private account feed requires login as that account")

    posts = _iter_posts_by_author(st, author=account)

    filtered: list[dict[str, Any]] = []
    for obj in posts:
        obj_id = _str_param(obj.get("id") or obj.get("post_id") or "").strip()
        created_at_nonce = int(obj.get("created_at_nonce", 0) or 0)

        vis = _str_param(obj.get("visibility"), "public").strip().lower() or "public"

        if visibility == "public":
            if vis != "public":
                continue
        elif visibility == "private":
            if vis != "private":
                continue
        elif visibility == "all":
            # If not owner, behave like public.
            if not is_owner and vis != "public":
                continue
        else:
            # Unknown -> fail closed to public.
            if vis != "public":
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

    return {"ok": True, "account": account, "items": page, "next_cursor": next_cursor}
