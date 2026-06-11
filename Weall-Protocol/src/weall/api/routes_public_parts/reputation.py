from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.routes_public_parts.common import _snapshot
from weall.api.security import require_account_session
from weall.runtime.reputation_matrix import derive_reputation_matrix

router = APIRouter()


Json = dict[str, Any]


def _viewer_for_request(request: Request, state: Json) -> str:
    try:
        return str(require_account_session(request, state) or "").strip()
    except PermissionError:
        return ""


@router.get("/reputation/{account}/summary")
def v1_reputation_summary(account: str, request: Request) -> Json:
    """Return the deterministic public Reputation Matrix summary for an account."""
    st = _snapshot(request)
    viewer = _viewer_for_request(request, st)
    reveal_private = bool(viewer and viewer == account)
    return derive_reputation_matrix(st, account, reveal_private=reveal_private, include_events=False)


@router.get("/reputation/{account}/events")
def v1_reputation_events(account: str, request: Request) -> Json:
    """Return deterministic Reputation Matrix event details for an account.

    Public callers receive public events only. The account owner receives private
    internal dimensions as well when a valid account session is present.
    """
    st = _snapshot(request)
    viewer = _viewer_for_request(request, st)
    reveal_private = bool(viewer and viewer == account)
    matrix = derive_reputation_matrix(st, account, reveal_private=reveal_private, include_events=True)
    return {
        "ok": True,
        "version": matrix.get("version"),
        "account_id": account,
        "deterministic": True,
        "visibility": matrix.get("visibility"),
        "events": matrix.get("events", []),
        "event_count": matrix.get("event_count", 0),
    }
