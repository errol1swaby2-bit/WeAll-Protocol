from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import ValidationError

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import (
    _att_pool,
    _executor,
    _read_json_limited,
    _require_registered_signer_for_attestation,
    _snapshot,
)
from weall.crypto.sig import strict_tx_sig_domain_enabled
from weall.ledger.state import LedgerView
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_schema import validate_tx_envelope

router = APIRouter()


def _validate_public_attestation_chain_id(*, body: dict, expected_chain_id: str) -> None:
    expected = str(expected_chain_id or "").strip()
    actual = body.get("chain_id")
    actual2 = str(actual).strip() if isinstance(actual, str) else ""

    if strict_tx_sig_domain_enabled() and not actual2:
        raise ApiError.forbidden(
            "missing_chain_id",
            "chain_id is required for public attestation submission",
            {"expected_chain_id": expected},
        )

    if actual2 and expected and actual2 != expected:
        raise ApiError.forbidden(
            "chain_id_mismatch",
            "attestation chain_id does not match this node",
            {"expected_chain_id": expected, "chain_id": actual2},
        )


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

    body = await _read_json_limited(
        request, max_bytes_env="WEALL_MAX_HTTP_TX_BYTES", default_max_bytes=256 * 1024
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "Body must be a tx envelope object", {})

    try:
        validate_tx_envelope(body)
    except ValidationError as ve:
        raise ApiError.bad_request(
            "invalid_tx",
            "attestation envelope failed schema validation",
            {"errors": ve.errors()},
        )

    tx_type = str(body.get("tx_type") or "").strip().upper()
    if tx_type != "BLOCK_ATTEST":
        raise ApiError.forbidden(
            "invalid_tx_type",
            "public attestation endpoint only accepts BLOCK_ATTEST",
            {"tx_type": tx_type},
        )

    if str(body.get("signer") or "").strip().upper() == "SYSTEM" or bool(body.get("system", False)):
        raise ApiError.forbidden(
            "system_tx_forbidden",
            "system-only txs cannot be submitted through the public attestation endpoint",
            {"tx_type": tx_type, "signer": body.get("signer")},
        )

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)

    signer = str(body.get("signer") or "").strip()
    _require_registered_signer_for_attestation(ledger=ledger, signer=signer)
    _validate_public_attestation_chain_id(
        body=body, expected_chain_id=str(getattr(ex, "chain_id", "") or "")
    )

    sig = str(body.get("sig") or "").strip()
    if not sig:
        raise ApiError.forbidden(
            "missing_sig",
            "signature is required for public attestation submission",
            {"tx_type": tx_type, "signer": signer},
        )

    if not verify_tx_signature(st if isinstance(st, dict) else {}, body):
        raise ApiError.forbidden(
            "bad_sig",
            "signature verification failed",
            {"tx_type": tx_type, "signer": signer},
        )

    payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
    block_id = str(payload.get("block_id") or payload.get("id") or "").strip()
    if not block_id:
        raise ApiError.bad_request("invalid_payload", "missing payload.block_id", {})

    payload_validator = str(payload.get("validator") or "").strip()
    if payload_validator and payload_validator != signer:
        raise ApiError.forbidden(
            "validator_mismatch",
            "payload.validator must match signer",
            {"signer": signer, "payload_validator": payload_validator},
        )

    normalized_payload = dict(payload)
    normalized_payload["validator"] = signer
    body["payload"] = normalized_payload
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
