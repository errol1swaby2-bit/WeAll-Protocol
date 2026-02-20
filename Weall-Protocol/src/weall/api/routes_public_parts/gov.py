# src/weall/api/routes_public_parts/gov.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request

from weall.api.errors import ApiError

from weall.api.routes_public_parts.common import (
    _int_param,
    _snapshot,
)

router = APIRouter()


def _proposals_by_id_from_snapshot(st: Dict[str, Any]) -> Dict[str, Any]:
    """Return proposals-by-id mapping from the canonical runtime snapshot.

    Canonical (current) state surface:
      st["gov_proposals_by_id"]

    Legacy/alternate surface (older UI expectations):
      st["gov"]["proposals"]["by_id"]
    """

    by_id = st.get("gov_proposals_by_id")
    if isinstance(by_id, dict):
        return by_id

    gov = st.get("gov")
    if not isinstance(gov, dict):
        return {}

    proposals = gov.get("proposals")
    if not isinstance(proposals, dict):
        return {}

    by_id = proposals.get("by_id")
    if not isinstance(by_id, dict):
        return {}
    return by_id


def _normalize_proposal(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure a stable shape for API consumers.

    Internally, governance uses "proposal_id".
    Some clients expect "id".
    """
    pid = obj.get("proposal_id") or obj.get("id")
    if pid and "id" not in obj:
        obj = dict(obj)
        obj["id"] = pid
    return obj


@router.get("/v1/gov/proposals")
def v1_gov_proposals(request: Request):
    st = _snapshot(request)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 50)
    limit = max(1, min(200, limit))

    by_id = _proposals_by_id_from_snapshot(st)
    if not by_id:
        return {"ok": True, "items": []}

    items: List[dict] = []
    for _, obj in by_id.items():
        if isinstance(obj, dict):
            items.append(_normalize_proposal(obj))

    # stable most-recent-first if created_at_nonce exists
    items.sort(
        key=lambda x: (
            int(x.get("created_at_nonce", 0) or 0),
            str(x.get("proposal_id") or x.get("id") or ""),
        ),
        reverse=True,
    )
    return {"ok": True, "items": items[:limit]}


@router.get("/v1/gov/proposals/{proposal_id}")
def v1_gov_proposal_get(proposal_id: str, request: Request):
    st = _snapshot(request)
    by_id = _proposals_by_id_from_snapshot(st)
    if not by_id:
        raise ApiError.not_found("not_found", "Proposal not found")

    # Accept either canonical key or legacy id.
    obj = by_id.get(proposal_id)
    if not isinstance(obj, dict):
        # fallback: scan for a proposal whose id/proposal_id matches
        for _, v in by_id.items():
            if not isinstance(v, dict):
                continue
            pid = v.get("proposal_id") or v.get("id")
            if pid == proposal_id:
                obj = v
                break

    if not isinstance(obj, dict):
        raise ApiError.not_found("not_found", "Proposal not found")

    return {"ok": True, "proposal": _normalize_proposal(obj)}
