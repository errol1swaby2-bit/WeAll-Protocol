from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.routes_public_parts.common import _snapshot
from weall.api.security import require_account_session
from weall.runtime.reputation_events import EVENT_REGISTRY, derive_role_eligibility, registry_payload
from weall.runtime.reputation_matrix import derive_reputation_matrix
from weall.runtime.reputation_progression import reputation_action_map, reputation_progression_status

router = APIRouter()


Json = dict[str, Any]


def _viewer_for_request(request: Request, state: Json) -> str:
    try:
        return str(require_account_session(request, state) or "").strip()
    except PermissionError:
        return ""
    except Exception:
        return ""


def _reveal_restricted(viewer: str, account: str) -> bool:
    # Public-only reputation rule: owner authentication does not reveal extra
    # protocol-meaning reputation dimensions. The parameter is retained only for
    # compatibility with existing helper call sites.
    return False


@router.get("/reputation/me")
def v1_reputation_me(request: Request) -> Json:
    """Return the authenticated account's public Reputation Matrix view."""
    st = _snapshot(request)
    viewer = str(require_account_session(request, st) or "").strip()
    matrix = derive_reputation_matrix(st, viewer, reveal_restricted=False, include_events=True)
    matrix["owner_view"] = True
    matrix["public_only"] = True
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


@router.get("/reputation/action-map")
def v1_reputation_action_map() -> Json:
    actions = reputation_action_map()
    return {
        "ok": True,
        "schema": "weall.reputation_action_map.v1_5",
        "action_count": len(actions),
        "actions": actions,
        "truth_boundary": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
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
    reveal_restricted = _reveal_restricted(viewer, account)
    return derive_reputation_matrix(st, account, reveal_restricted=reveal_restricted, include_events=False)


@router.get("/reputation/{account}/matrix")
def v1_reputation_matrix(account: str, request: Request) -> Json:
    """Return matrix dimensions, eligibility, and recent events for an account."""
    st = _snapshot(request)
    viewer = _viewer_for_request(request, st)
    reveal_restricted = _reveal_restricted(viewer, account)
    return derive_reputation_matrix(st, account, reveal_restricted=reveal_restricted, include_events=True)


@router.get("/reputation/{account}/eligibility")
def v1_reputation_eligibility(account: str, request: Request) -> Json:
    """Return role eligibility booleans with backend-derived reasons."""
    st = _snapshot(request)
    matrix = derive_reputation_matrix(st, account, reveal_restricted=False, include_events=False)
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

    All callers receive the same public-inspectable reputation events. Account
    owner authentication does not reveal private protocol-meaning dimensions.
    """
    st = _snapshot(request)
    viewer = _viewer_for_request(request, st)
    reveal_restricted = _reveal_restricted(viewer, account)
    matrix = derive_reputation_matrix(st, account, reveal_restricted=reveal_restricted, include_events=True)
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


@router.get("/accounts/{account}/reputation-status")
def v1_account_reputation_status(account: str, request: Request) -> Json:
    st = _snapshot(request)
    return reputation_progression_status(st, account)


@router.get("/accounts/{account}/reputation-progression-status")
def v1_account_reputation_progression_status(account: str, request: Request) -> Json:
    st = _snapshot(request)
    return reputation_progression_status(st, account)
