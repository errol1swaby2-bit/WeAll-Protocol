from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.routes_public_parts.common import _snapshot
from weall.api.security import require_account_session
from weall.runtime.reputation_events import EVENT_REGISTRY, derive_role_eligibility, registry_payload
from weall.runtime.reputation_matrix import derive_reputation_matrix

router = APIRouter()


Json = dict[str, Any]


def _viewer_for_request(request: Request, state: Json) -> str:
    try:
        return str(require_account_session(request, state) or "").strip()
    except PermissionError:
        return ""
    except Exception:
        return ""


def _reveal_private(viewer: str, account: str) -> bool:
    return bool(viewer and (viewer == account or viewer.lstrip("@") == str(account or "").lstrip("@")))


@router.get("/reputation/me")
def v1_reputation_me(request: Request) -> Json:
    """Return the authenticated account's full Reputation Matrix owner view."""
    st = _snapshot(request)
    viewer = str(require_account_session(request, st) or "").strip()
    matrix = derive_reputation_matrix(st, viewer, reveal_private=True, include_events=True)
    matrix["owner_view"] = True
    return matrix


@router.get("/reputation/event-codes")
def v1_reputation_event_codes() -> Json:
    """Return the canonical v1.5 Reputation Matrix event registry."""
    payload = registry_payload()
    return {
        "ok": True,
        "schema": payload["schema"],
        "version": payload["version"],
        "dimension_count": payload["dimension_count"],
        "event_count": payload["event_count"],
        "dimensions": payload["dimensions"],
        "severity_scale": payload["severity_scale"],
        "events": payload["events"],
    }


@router.get("/reputation/{account}")
def v1_reputation_account(account: str, request: Request) -> Json:
    """Alias for the public account Reputation Matrix summary."""
    return v1_reputation_summary(account, request)


@router.get("/reputation/{account}/summary")
def v1_reputation_summary(account: str, request: Request) -> Json:
    """Return the deterministic public Reputation Matrix summary for an account."""
    st = _snapshot(request)
    viewer = _viewer_for_request(request, st)
    reveal_private = _reveal_private(viewer, account)
    return derive_reputation_matrix(st, account, reveal_private=reveal_private, include_events=False)


@router.get("/reputation/{account}/matrix")
def v1_reputation_matrix(account: str, request: Request) -> Json:
    """Return matrix dimensions, eligibility, and recent events for an account."""
    st = _snapshot(request)
    viewer = _viewer_for_request(request, st)
    reveal_private = _reveal_private(viewer, account)
    return derive_reputation_matrix(st, account, reveal_private=reveal_private, include_events=True)


@router.get("/reputation/{account}/eligibility")
def v1_reputation_eligibility(account: str, request: Request) -> Json:
    """Return role eligibility booleans with backend-derived reasons."""
    st = _snapshot(request)
    matrix = derive_reputation_matrix(st, account, reveal_private=False, include_events=False)
    return {
        "ok": True,
        "account_id": account,
        "deterministic": True,
        "eligibility": matrix.get("eligibility") or derive_role_eligibility(st, account),
        "canonical_dimensions": matrix.get("canonical_dimensions", {}),
    }


@router.get("/reputation/{account}/events")
def v1_reputation_events(account: str, request: Request) -> Json:
    """Return deterministic Reputation Matrix event details for an account.

    Public callers receive public events only. The account owner receives private
    internal dimensions as well when a valid account session is present.
    """
    st = _snapshot(request)
    viewer = _viewer_for_request(request, st)
    reveal_private = _reveal_private(viewer, account)
    matrix = derive_reputation_matrix(st, account, reveal_private=reveal_private, include_events=True)
    return {
        "ok": True,
        "version": matrix.get("version"),
        "account_id": account,
        "deterministic": True,
        "visibility": matrix.get("visibility"),
        "events": matrix.get("events", []),
        "event_count": matrix.get("event_count", 0),
        "event_history_root": matrix.get("event_history_root"),
        "registry_event_count": len(EVENT_REGISTRY),
    }
