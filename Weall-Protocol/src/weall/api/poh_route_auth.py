from __future__ import annotations

"""Fail-closed authorization boundary for privacy-sensitive PoH reads.

The PoH API intentionally has a mix of public commitment/status surfaces and
viewer/reviewer scoped queues.  Keep that distinction at the router boundary so
a caller-supplied account or juror selector can never substitute for the
authenticated session principal.

Tier-2 and Live full-case handlers currently serialize reviewer/evidence maps.
Until those handlers have a separately generated public projection, their full
case views are participant-only here.  The async generic case handler already
has its own viewer-aware restricted-evidence projection and remains public.
"""

from typing import Any

from fastapi import Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _snapshot
from weall.api.security import require_account_session

Json = dict[str, Any]


_SCOPED_QUERY_READS: dict[str, str] = {
    "/v1/poh/async/my-cases": "account",
    "/v1/poh/async/juror-cases": "juror",
    "/v1/poh/tier2/my-cases": "account",
    "/v1/poh/tier2/juror-cases": "juror",
    "/v1/poh/live/my-cases": "account",
    "/v1/poh/live/assigned": "juror",
}

_CASE_READ_PREFIXES: dict[str, str] = {
    "/v1/poh/tier2/case/": "tier2_cases",
    "/v1/poh/live/case/": "live_cases",
}


def _principal(request: Request, state: Json) -> str:
    try:
        return str(require_account_session(request, state) or "").strip()
    except PermissionError as exc:
        raise ApiError.forbidden(
            "poh_session_required",
            "A valid account session is required for this Proof-of-Humanity read.",
            {"reason": str(exc)},
        ) from exc


def _case_record(state: Json, *, collection: str, case_id: str) -> Json | None:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        return None
    cases = poh.get(collection)
    if not isinstance(cases, dict):
        return None
    case = cases.get(case_id)
    return case if isinstance(case, dict) else None


def _case_participants(case: Json) -> set[str]:
    participants: set[str] = set()
    for field in ("account_id", "requestor"):
        value = str(case.get(field) or "").strip()
        if value:
            participants.add(value)

    jurors = case.get("jurors")
    if isinstance(jurors, dict):
        participants.update(str(value).strip() for value in jurors.keys() if str(value).strip())
    elif isinstance(jurors, list):
        participants.update(str(value).strip() for value in jurors if str(value).strip())

    assigned = case.get("assigned_jurors")
    if isinstance(assigned, list):
        participants.update(str(value).strip() for value in assigned if str(value).strip())

    return participants


def enforce_poh_read_authorization(request: Request) -> None:
    """Authorize sensitive PoH GETs before their route handler executes."""

    if str(request.method or "").upper() != "GET":
        return

    path = str(request.url.path or "").rstrip("/") or "/"

    selector = _SCOPED_QUERY_READS.get(path)
    if selector is not None:
        state = _snapshot(request)
        principal = _principal(request, state)
        requested = str(request.query_params.get(selector) or "").strip()
        if not requested or requested != principal:
            raise ApiError.forbidden(
                "poh_session_identity_mismatch",
                "The requested PoH queue must match the authenticated account session.",
                {"selector": selector},
            )
        return

    for prefix, collection in _CASE_READ_PREFIXES.items():
        if not path.startswith(prefix):
            continue
        state = _snapshot(request)
        principal = _principal(request, state)
        case_id = str(request.path_params.get("case_id") or path[len(prefix) :]).strip()
        case = _case_record(state, collection=collection, case_id=case_id)
        # Preserve the route's own not-found semantics, but only after a valid
        # session has crossed this privacy boundary.
        if case is None:
            return
        if principal not in _case_participants(case):
            raise ApiError.forbidden(
                "poh_case_viewer_forbidden",
                "The authenticated account is not a participant in this PoH case.",
                {"case_id": case_id},
            )
        return


__all__ = ["enforce_poh_read_authorization"]
