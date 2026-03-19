# src/weall/api/routes_public_parts/state.py
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

Json = dict[str, Any]


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
        raise HTTPException(
            status_code=503, detail={"code": "not_ready", "message": "executor not ready"}
        )

    st = ex.snapshot()
    if not isinstance(st, dict):
        return {"ok": False, "error": {"code": "bad_state", "message": "snapshot not a dict"}}

    # Keep response shape stable.
    return {"ok": True, "state": st}


@router.get("/state/block/{block_id}")
def state_block(block_id: str, request: Request) -> Json:
    ex = getattr(request.app.state, "executor", None)
    if ex is None:
        raise HTTPException(
            status_code=503, detail={"code": "not_ready", "message": "executor not ready"}
        )
    fn = getattr(ex, "get_block_by_id", None)
    if not callable(fn):
        raise HTTPException(
            status_code=501, detail={"code": "not_supported", "message": "block lookup unavailable"}
        )
    blk = fn(str(block_id or ""))
    if not isinstance(blk, dict):
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "block not found"}
        )
    return {"ok": True, "block": blk}
