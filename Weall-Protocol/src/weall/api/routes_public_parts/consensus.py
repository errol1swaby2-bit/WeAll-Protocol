from __future__ import annotations

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.ledger.state import LedgerView

from weall.api.routes_public_parts.common import (
    _att_pool,
    _executor,
    _snapshot,
    _require_registered_signer_for_attestation,
)

router = APIRouter()


@router.post("/consensus/attest/submit")
async def consensus_attest_submit(request: Request):
    """
    Submit a validator attestation into the SQLite-backed attestation pool.

    Mounted under /v1 by routes_public.py, so the full path is:
      POST /v1/consensus/attest/submit

    The pool persists attestations keyed by a derived att_id (not trusted from client),
    and also stores a block_id column for efficient fetch.

    We derive block_id from the payload and set it on the top-level envelope before
    persistence to match the SQLite schema.
    """
    ex = _executor(request)
    ap = _att_pool(request)

    body = await request.json()
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "Body must be an attestation object", {})

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)

    signer = str(body.get("signer") or "").strip()
    _require_registered_signer_for_attestation(ledger=ledger, signer=signer)

    payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
    block_id = str(payload.get("block_id") or payload.get("id") or "").strip()
    if not block_id:
        raise ApiError.bad_request("invalid_payload", "missing payload.block_id", {})

    body["block_id"] = block_id

    if hasattr(ex, "submit_attestation"):
        meta = ex.submit_attestation(body)
    else:
        meta = ap.add(body)

    if not isinstance(meta, dict) or not meta.get("ok"):
        raise ApiError.forbidden(
            str(meta.get("error") if isinstance(meta, dict) else "submit_failed"),
            "attestation rejected",
            {"details": meta if isinstance(meta, dict) else {"meta": str(meta)}},
        )

    att_id = str(meta.get("att_id") or "").strip()
    ap_size = int(getattr(ap, "size", lambda: 0)() if ap is not None else 0)

    return {
        "ok": True,
        "att_id": att_id,
        "attestation_pool_size": ap_size,
        "block_id": block_id,
    }
