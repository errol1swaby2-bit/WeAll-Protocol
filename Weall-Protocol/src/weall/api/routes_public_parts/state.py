# src/weall/api/routes_public_parts/state.py
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request


router = APIRouter()

Json = Dict[str, Any]


@router.get("/state/snapshot")
def state_snapshot(request: Request) -> Json:
    """Return the node's current ledger snapshot.

    This is a public debugging/UX endpoint used by the web front.

    Production note:
      - This endpoint can grow large over time.
      - Operators may disable it at the edge or replace it with a pruned view.
    """

    ex = getattr(request.app.state, "executor", None)
    if ex is None:
        raise HTTPException(status_code=503, detail={"code": "not_ready", "message": "executor not ready"})

    st = ex.snapshot()
    if not isinstance(st, dict):
        return {"ok": False, "error": {"code": "bad_state", "message": "snapshot not a dict"}}

    # Keep response shape stable.
    return {"ok": True, "state": st}
