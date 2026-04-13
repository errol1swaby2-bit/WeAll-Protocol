# src/weall/api/routes_public_parts/gov.py
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _int_param, _snapshot

router = APIRouter()


def _proposals_by_id_from_snapshot(st: dict[str, Any]) -> dict[str, Any]:
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


def _as_vote_map(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _count_map(m: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {"yes": 0, "no": 0, "abstain": 0}
    for _, v in sorted(m.items(), key=lambda item: str(item[0])):
        if not isinstance(v, dict):
            continue
        k = str(v.get("vote") or "").strip().lower()
        if k == "yes":
            out["yes"] += 1
        elif k == "no":
            out["no"] += 1
        elif k:
            out["abstain"] += 1
    return out


def _normalize_proposal(obj: dict[str, Any]) -> dict[str, Any]:
    """Ensure a stable shape for API consumers.

    Internally, governance uses "proposal_id" and "stage".
    Some clients expect "id" and "status".
    """

    out = dict(obj)
    pid = out.get("proposal_id") or out.get("id")
    stage = out.get("stage") or out.get("status") or "unknown"

    if pid and "id" not in out:
        out["id"] = pid
    if stage and "status" not in out:
        out["status"] = stage

    poll_votes = _as_vote_map(out.get("poll_votes"))
    votes = _as_vote_map(out.get("votes"))
    poll_counts = _count_map(poll_votes)
    counts = _count_map(votes)

    out["poll_votes"] = poll_votes
    out["votes"] = votes
    out["poll_counts"] = poll_counts
    out["counts"] = counts
    out["poll_vote_total"] = int(sum(poll_counts.values()))
    out["vote_total"] = int(sum(counts.values()))
    out["has_actions"] = bool(isinstance(out.get("actions"), list) and out.get("actions"))
    out["execution_count"] = len(out.get("executions")) if isinstance(out.get("executions"), list) else 0
    return out


def _proposal_obj_from_snapshot(st: dict[str, Any], proposal_id: str) -> dict[str, Any]:
    """Fetch a proposal object by id from snapshot, supporting canonical + legacy IDs."""

    by_id = _proposals_by_id_from_snapshot(st)
    if not by_id:
        raise ApiError.not_found("not_found", "Proposal not found")

    obj = by_id.get(proposal_id)
    if isinstance(obj, dict):
        return obj

    # fallback: scan for a proposal whose id/proposal_id matches
    for _, v in by_id.items():
        if not isinstance(v, dict):
            continue
        pid = v.get("proposal_id") or v.get("id")
        if pid == proposal_id:
            return v

    raise ApiError.not_found("not_found", "Proposal not found")


@router.get("/gov/proposals")
def v1_gov_proposals(request: Request):
    """List governance proposals.

    Mounted under /v1:
      GET /v1/gov/proposals
    """

    st = _snapshot(request)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 50)
    limit = max(1, min(200, limit))

    by_id = _proposals_by_id_from_snapshot(st)
    if not by_id:
        return {"ok": True, "items": []}

    items: list[dict[str, Any]] = []
    for _, obj in by_id.items():
        if isinstance(obj, dict):
            items.append(_normalize_proposal(obj))

    items.sort(
        key=lambda x: (
            int(x.get("created_at_height", 0) or 0),
            str(x.get("proposal_id") or x.get("id") or ""),
        ),
        reverse=True,
    )
    return {"ok": True, "items": items[:limit]}


@router.get("/gov/proposals/{proposal_id}")
def v1_gov_proposal_get(proposal_id: str, request: Request):
    """Get a governance proposal by id.

    Mounted under /v1:
      GET /v1/gov/proposals/{proposal_id}
    """

    st = _snapshot(request)
    obj = _proposal_obj_from_snapshot(st, proposal_id)
    return {"ok": True, "proposal": _normalize_proposal(obj)}


@router.get("/gov/proposals/{proposal_id}/votes")
def v1_gov_proposal_votes(proposal_id: str, request: Request):
    """Get votes for a governance proposal.

    Mounted under /v1:
      GET /v1/gov/proposals/{proposal_id}/votes
    """

    st = _snapshot(request)
    obj = _proposal_obj_from_snapshot(st, proposal_id)

    poll_votes = _as_vote_map(obj.get("poll_votes"))
    votes = _as_vote_map(obj.get("votes"))

    return {
        "ok": True,
        "proposal_id": str(obj.get("proposal_id") or obj.get("id") or proposal_id),
        "stage": str(obj.get("stage") or obj.get("status") or "unknown"),
        "poll_votes": poll_votes,
        "votes": votes,
        "poll_counts": _count_map(poll_votes),
        "counts": _count_map(votes),
    }
