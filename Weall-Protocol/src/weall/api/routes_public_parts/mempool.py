from __future__ import annotations

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import (
    _executor,
    _mempool,
    _read_json_limited,
    _require_registered_signer_for_user_tx,
    _snapshot,
)
from weall.crypto.sig import strict_tx_sig_domain_enabled
from weall.ledger.state import LedgerView
from weall.runtime.sigverify import verify_tx_signature

router = APIRouter()


def _net_node(request: Request):
    return getattr(request.app.state, "net_node", None)


def _mempool_requires_sig_by_default() -> bool:
    return True


def _validate_public_tx_chain_id(*, body: dict, expected_chain_id: str) -> None:
    expected = str(expected_chain_id or "").strip()
    actual = body.get("chain_id")
    actual2 = str(actual).strip() if isinstance(actual, str) else ""

    if strict_tx_sig_domain_enabled() and not actual2:
        raise ApiError.forbidden(
            "missing_chain_id",
            "chain_id is required for public mempool submission",
            {"expected_chain_id": expected},
        )

    if actual2 and expected and actual2 != expected:
        raise ApiError.forbidden(
            "chain_id_mismatch",
            "tx chain_id does not match this node",
            {"expected_chain_id": expected, "chain_id": actual2},
        )


@router.post("/mempool/submit")
async def mempool_submit(request: Request):
    """
    Public mempool submission endpoint.

    SECURITY:
      - Never accept system receipts over public HTTP.
      - Never accept signer == SYSTEM over public HTTP.
      - Mirror tx-submit signature + chain-id replay-domain checks.
    """
    ex = _executor(request)
    mp = _mempool(request)

    body = await _read_json_limited(
        request, max_bytes_env="WEALL_MAX_HTTP_TX_BYTES", default_max_bytes=256 * 1024
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "Body must be a tx envelope object", {})

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)

    tx_type = str(body.get("tx_type") or "").strip()
    signer = str(body.get("signer") or "").strip()
    _validate_public_tx_chain_id(
        body=body, expected_chain_id=str(getattr(ex, "chain_id", "") or "")
    )

    if signer == "SYSTEM" or bool(body.get("system", False)):
        raise ApiError.forbidden(
            "system_tx_forbidden",
            "system-only txs cannot be submitted through the public mempool endpoint",
            {"tx_type": tx_type, "signer": signer},
        )

    _require_registered_signer_for_user_tx(ledger=ledger, tx_type=tx_type, signer=signer)

    if _mempool_requires_sig_by_default():
        if not isinstance(body.get("sig"), str) or not str(body.get("sig") or "").strip():
            raise ApiError.forbidden(
                "missing_sig",
                "signature is required for public mempool submission",
                {"tx_type": tx_type, "signer": signer},
            )
        if not verify_tx_signature(st if isinstance(st, dict) else {}, body):
            raise ApiError.forbidden(
                "bad_sig",
                "signature verification failed",
                {"tx_type": tx_type, "signer": signer},
            )

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

    try:
        nn = _net_node(request)
        if nn is not None and tx_id:
            msg = nn.build_tx_envelope_msg(body, client_tx_id=tx_id)
            nn.gossip_announce_tx(msg)
    except Exception:
        pass

    return {"ok": True, "tx_id": tx_id, "mempool_size": mp_size}
