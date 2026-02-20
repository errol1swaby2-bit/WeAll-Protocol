# src/weall/api/routes_public_parts/mempool.py
from __future__ import annotations

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.ledger.state import LedgerView

from weall.api.routes_public_parts.common import (
    _executor,
    _mempool,
    _snapshot,
    _require_registered_signer_for_user_tx,
)

router = APIRouter()


def _net_node(request: Request):
    return getattr(request.app.state, "net_node", None)


@router.post("/mempool/submit")
async def mempool_submit(request: Request):
    """
    Public mempool submission endpoint.

    SECURITY:
      - Never accept system receipts over public HTTP.
      - Never accept signer == SYSTEM over public HTTP.
    """
    ex = _executor(request)
    mp = _mempool(request)

    body = await request.json()
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "Body must be a tx envelope object", {})

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)

    tx_type = str(body.get("tx_type") or "").strip()
    signer = str(body.get("signer") or "").strip()

    # Hard fail-closed: receipts are block/system-only, and must not come from public mempool.
    if signer == "SYSTEM" or bool(body.get("system", False)):
        raise ApiError.forbidden(
            "system_tx_forbidden",
            "system-only txs cannot be submitted through the public mempool endpoint",
            {"tx_type": tx_type, "signer": signer},
        )

    _require_registered_signer_for_user_tx(ledger=ledger, tx_type=tx_type, signer=signer)

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

    tx_id = str(meta.get("tx_id") or "").strip()
    mp_size = int(getattr(mp, "size", lambda: 0)() if mp is not None else 0)

    # Best-effort mesh propagation
    try:
        nn = _net_node(request)
        if nn is not None and tx_id:
            msg = nn.build_tx_envelope_msg(body, client_tx_id=tx_id)
            nn.gossip_announce_tx(msg)
    except Exception:
        pass

    return {"ok": True, "tx_id": tx_id, "mempool_size": mp_size}
