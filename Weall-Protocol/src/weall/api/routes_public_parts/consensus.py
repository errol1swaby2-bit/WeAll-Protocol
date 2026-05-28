from __future__ import annotations

import json
from typing import Any

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


def _boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value or "").strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _value_boolish(obj: Any, name: str, default: bool = False) -> bool:
    value = getattr(obj, name, default)
    if callable(value):
        try:
            value = value()
        except Exception:
            value = default
    return _boolish(value)


@router.get("/consensus/block-production/readiness")
def consensus_block_production_readiness(request: Request):
    """Read-only production-orientation status for block production.

    This does not grant proposer authority and never produces a block.  It gives
    reviewers and the UI one canonical place to inspect whether this node is in
    observer mode, whether the local producer loop is running, and whether the
    current posture is only local rehearsal or a production-profile candidate.
    """
    ex = _executor(request)
    st = _snapshot(request)
    meta = st.get("meta") if isinstance(st.get("meta"), dict) else {}
    mode = str(meta.get("mode") or meta.get("runtime_mode") or "").strip().lower()
    observer_mode = bool(meta.get("observer_mode", False)) or _value_boolish(ex, "observer_mode", False)
    block_loop_running = bool(getattr(ex, "block_loop_running", False))
    block_loop_unhealthy = bool(getattr(ex, "block_loop_unhealthy", False))
    last_error = str(getattr(ex, "block_loop_last_error", "") or "").strip()
    height = int(st.get("height") or 0) if isinstance(st, dict) else 0
    bft_enabled = _boolish(meta.get("bft_enabled")) or _value_boolish(ex, "bft_enabled", False)
    validator_signing = _boolish(meta.get("validator_signing_enabled")) or _value_boolish(ex, "validator_signing_enabled", False)

    production_profile_candidate = bool(mode == "prod" and not observer_mode and not block_loop_unhealthy)
    can_locally_produce = bool(block_loop_running and not block_loop_unhealthy and not observer_mode)

    return {
        "ok": True,
        "height": height,
        "mode": mode or "unknown",
        "observer_mode": observer_mode,
        "block_loop": {
            "running": block_loop_running,
            "unhealthy": block_loop_unhealthy,
            "last_error": last_error,
            "consecutive_failures": int(getattr(ex, "block_loop_consecutive_failures", 0) or 0),
        },
        "authority": {
            "validator_signing_enabled": validator_signing,
            "bft_enabled": bft_enabled,
            "observer_cannot_produce": observer_mode,
        },
        "can_locally_produce": can_locally_produce,
        "production_profile_candidate": production_profile_candidate,
        "public_multi_validator_bft_ready": False,
        "claim": "This is read-only block production posture evidence. It does not grant authority or prove public multi-validator BFT.",
    }

def _as_dict_any(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _latest_block_from_executor(ex: Any, st: dict[str, Any]) -> dict[str, Any]:
    """Return the latest committed block object if the local DB/state can prove one.

    This is read-only evidence for production-profile block-production rehearsal.
    The endpoint intentionally never creates a block and never grants proposer
    authority; it only exposes the block roots already committed by the runtime.
    """

    # Prefer the atomic SQLite block table because it contains the canonical block
    # object with header roots and receipts.  Fall back to the ancestry map in
    # state so tests/lightweight fixtures can still surface limited evidence.
    db = getattr(ex, "_db", None)
    try:
        if db is not None and hasattr(db, "connection"):
            with db.connection() as con:
                row = con.execute(
                    "SELECT block_json FROM blocks ORDER BY height DESC LIMIT 1;"
                ).fetchone()
                if row is not None:
                    raw = row["block_json"] if "block_json" in row.keys() else row[0]
                    block = json.loads(str(raw))
                    if isinstance(block, dict):
                        return block
    except Exception:
        pass

    blocks = st.get("blocks") if isinstance(st.get("blocks"), dict) else {}
    tip = str(st.get("tip") or "").strip()
    rec = _as_dict_any(blocks.get(tip)) if tip else {}
    if rec:
        return {
            "block_id": tip,
            "height": int(rec.get("height") or st.get("height") or 0),
            "block_ts_ms": int(rec.get("block_ts_ms") or st.get("tip_ts_ms") or 0),
            "prev_block_id": str(rec.get("prev_block_id") or ""),
            "header": {
                "state_root": "",
                "receipts_root": "",
                "helper_execution_root": "",
            },
            "txs": [],
            "receipts": [],
            "state_ancestry_only": True,
        }
    return {}


def block_production_proof_from_state(ex: Any, st: dict[str, Any]) -> dict[str, Any]:
    block = _latest_block_from_executor(ex, st if isinstance(st, dict) else {})
    header = _as_dict_any(block.get("header"))
    block_id = str(block.get("block_id") or "").strip()
    height = int(block.get("height") or header.get("height") or 0)
    receipts = block.get("receipts") if isinstance(block.get("receipts"), list) else []
    txs = block.get("txs") if isinstance(block.get("txs"), list) else []
    state_root = str(header.get("state_root") or "").strip()
    receipts_root = str(header.get("receipts_root") or "").strip()
    helper_root = str(header.get("helper_execution_root") or "").strip()
    block_hash = str(block.get("block_hash") or header.get("block_hash") or "").strip()
    ancestry_only = bool(block.get("state_ancestry_only"))
    has_root_evidence = bool(state_root and receipts_root and block_hash and not ancestry_only)
    return {
        "ok": True,
        "has_committed_block": bool(block_id and height > 0),
        "height": int(height),
        "block_id": block_id,
        "block_hash": block_hash,
        "prev_block_id": str(block.get("prev_block_id") or ""),
        "prev_block_hash": str(block.get("prev_block_hash") or header.get("prev_block_hash") or ""),
        "block_ts_ms": int(block.get("block_ts_ms") or header.get("block_ts_ms") or 0),
        "state_root": state_root,
        "receipts_root": receipts_root,
        "helper_execution_root": helper_root,
        "tx_count": int(len(txs)),
        "receipt_count": int(len(receipts)),
        "has_root_evidence": has_root_evidence,
        "state_ancestry_only": ancestry_only,
        "claim": "Latest committed local block evidence only; public multi-validator BFT still requires a separate adversarial proof.",
    }


@router.get("/consensus/block-production/proof")
def consensus_block_production_proof(request: Request):
    ex = _executor(request)
    st = _snapshot(request)
    proof = block_production_proof_from_state(ex, st if isinstance(st, dict) else {})
    readiness = consensus_block_production_readiness(request)
    proof["readiness"] = readiness
    return proof

