from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _executor, _mempool, _snapshot, _require_registered_signer_for_user_tx
from weall.ledger.state import LedgerView
from weall.runtime.mempool import compute_tx_id

router = APIRouter()

Json = Dict[str, Any]


def _tx_index_lookup(request: Request, tx_id: str) -> Optional[Json]:
    """Return tx_index row if present."""
    mp = _mempool(request)
    db = getattr(mp, "db", None)
    if db is None:
        return None
    t = str(tx_id or "").strip()
    if not t:
        return None
    try:
        with db.connection() as con:
            row = con.execute(
                "SELECT tx_id, height, block_id, tx_type, signer, included_ts_ms FROM tx_index WHERE tx_id=? LIMIT 1;",
                (t,),
            ).fetchone()
            if row is None:
                return None
            return {
                "tx_id": str(row["tx_id"]),
                "height": int(row["height"]),
                "block_id": str(row["block_id"]),
                "tx_type": str(row["tx_type"]),
                "signer": str(row["signer"]),
                "included_ts_ms": int(row["included_ts_ms"]),
            }
    except Exception:
        return None


@router.post("/tx/submit")
async def tx_submit(request: Request) -> Json:
    """Submit a user tx envelope.

    Goals:
      - idempotent submission (same tx_id + identical envelope => already_known)
      - fail-closed against SYSTEM / receipts over public HTTP
      - suitable for webfront failover across nodes

    Returns:
      { ok, tx_id, status: accepted|already_known, mempool_size }
    """
    ex = _executor(request)
    mp = _mempool(request)

    body = await request.json()
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "Body must be a tx envelope object", {})

    tx_type = str(body.get("tx_type") or "").strip()
    signer = str(body.get("signer") or "").strip()

    # Hard fail-closed: receipts are block/system-only, and must not come from public HTTP.
    if signer == "SYSTEM" or bool(body.get("system", False)):
        raise ApiError.forbidden(
            "system_tx_forbidden",
            "system-only txs cannot be submitted through the public tx endpoint",
            {"tx_type": tx_type, "signer": signer},
        )

    # Enforce signer registration / gating for user tx.
    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)
    _require_registered_signer_for_user_tx(ledger=ledger, tx_type=tx_type, signer=signer)

    # Compute deterministic id for idempotency.
    tx_id = compute_tx_id(body)

    already = False
    try:
        already = bool(getattr(mp, "contains", lambda _t: False)(tx_id))
    except Exception:
        already = False

    # submit
    if hasattr(ex, "submit_tx"):
        meta = ex.submit_tx(body)
    else:
        meta = mp.add(body)

    if not isinstance(meta, dict) or not meta.get("ok"):
        raise ApiError.forbidden(
            str(meta.get("error") if isinstance(meta, dict) else "submit_failed"),
            "tx rejected",
            {"details": meta if isinstance(meta, dict) else {"meta": str(meta)}},
        )

    out_tx_id = str(meta.get("tx_id") or tx_id).strip() or tx_id
    mp_size = int(getattr(mp, "size", lambda: 0)() if mp is not None else 0)

    return {
        "ok": True,
        "tx_id": out_tx_id,
        "status": "already_known" if already else "accepted",
        "mempool_size": mp_size,
    }


@router.get("/tx/status/{tx_id}")
def tx_status(request: Request, tx_id: str) -> Json:
    """Return tx status.

    Status values:
      - confirmed: tx included in a persisted block
      - pending: tx present in mempool
      - unknown: not known (or expired and not indexed)

    Returns:
      { ok, tx_id, status, height?, block_id?, included_ts_ms? }
    """
    t = str(tx_id or "").strip()
    if not t:
        raise ApiError.bad_request("bad_request", "missing tx_id", {})

    idx = _tx_index_lookup(request, t)
    if isinstance(idx, dict):
        return {
            "ok": True,
            "tx_id": t,
            "status": "confirmed",
            "height": int(idx.get("height") or 0),
            "block_id": str(idx.get("block_id") or ""),
            "included_ts_ms": int(idx.get("included_ts_ms") or 0),
            "tx_type": str(idx.get("tx_type") or ""),
            "signer": str(idx.get("signer") or ""),
        }

    mp = _mempool(request)
    try:
        if bool(getattr(mp, "contains", lambda _t: False)(t)):
            return {"ok": True, "tx_id": t, "status": "pending"}
    except Exception:
        pass

    return {"ok": True, "tx_id": t, "status": "unknown"}
