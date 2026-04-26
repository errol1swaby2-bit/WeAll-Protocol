from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from pydantic import ValidationError

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import (
    _executor,
    _mempool,
    _read_json_limited,
    _require_registered_signer_for_user_tx,
    _snapshot,
)
from weall.ledger.state import LedgerView
from weall.crypto.sig import strict_tx_sig_domain_enabled
from weall.runtime.mempool import compute_tx_id
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_schema import validate_tx_envelope

router = APIRouter()

Json = dict[str, Any]


_TX_PUBLIC_ENTRYPOINTS: dict[str, list[str]] = {
    "BLOCK_ATTEST": ["/v1/consensus/attest/submit"],
    "POH_TIER2_REQUEST_OPEN": ["/v1/poh/tier2/tx/request", "/v1/tx/submit"],
    "POH_TIER3_REQUEST_OPEN": ["/v1/poh/tier3/tx/request", "/v1/tx/submit"],
    "POH_TIER2_JUROR_ACCEPT": ["/v1/poh/tier2/tx/juror-accept", "/v1/tx/submit"],
    "POH_TIER2_JUROR_DECLINE": ["/v1/poh/tier2/tx/juror-decline", "/v1/tx/submit"],
    "POH_TIER2_REVIEW_SUBMIT": ["/v1/poh/tier2/tx/review", "/v1/tx/submit"],
    "POH_TIER3_JUROR_ACCEPT": ["/v1/poh/tier3/tx/juror-accept", "/v1/tx/submit"],
    "POH_TIER3_JUROR_DECLINE": ["/v1/poh/tier3/tx/juror-decline", "/v1/tx/submit"],
    "POH_TIER3_ATTENDANCE_MARK": ["/v1/poh/tier3/tx/attendance", "/v1/tx/submit"],
    "POH_TIER3_VERDICT_SUBMIT": ["/v1/poh/tier3/tx/verdict", "/v1/tx/submit"],
    "POH_EMAIL_RECEIPT_SUBMIT": ["/v1/poh/email/tx/receipt-submit", "/v1/tx/submit"],
}


def _default_public_entrypoints(origin: str, context: str) -> list[str]:
    origin_norm = str(origin or "").strip().upper()
    context_norm = str(context or "").strip().lower()
    routes: list[str] = []
    if context_norm == "mempool" and origin_norm in {"USER", "VALIDATOR"}:
        routes.append("/v1/tx/submit")
        routes.append("/v1/mempool/submit")
    return routes


def _tx_public_entrypoints(tx_type: str, origin: str, context: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for route in _TX_PUBLIC_ENTRYPOINTS.get(str(tx_type or "").strip(), []) + _default_public_entrypoints(origin, context):
        norm = str(route or "").strip()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        ordered.append(norm)
    return ordered


def _mode() -> str:
    return (os.environ.get("WEALL_MODE") or "prod").strip().lower() or "prod"


def _safe_mempool(request: Request):
    try:
        return _mempool(request)
    except Exception:
        return None


def _safe_executor(request: Request):
    try:
        return _executor(request)
    except Exception:
        return None


def _net_node(request: Request):
    return getattr(request.app.state, "net_node", None)


def _validate_public_tx_chain_id(*, body: Json, expected_chain_id: str) -> None:
    expected = str(expected_chain_id or "").strip()
    actual = body.get("chain_id")
    actual2 = str(actual).strip() if isinstance(actual, str) else ""

    if strict_tx_sig_domain_enabled() and not actual2:
        raise ApiError.forbidden(
            "missing_chain_id",
            "chain_id is required for public tx submission",
            {"expected_chain_id": expected},
        )

    if actual2 and expected and actual2 != expected:
        raise ApiError.forbidden(
            "chain_id_mismatch",
            "tx chain_id does not match this node",
            {"expected_chain_id": expected, "chain_id": actual2},
        )


def _tx_index_lookup(request: Request, tx_id: str) -> Json | None:
    """Return tx_index row if present."""
    mp = _safe_mempool(request)
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


def _tx_block_lookup(request: Request, tx_id: str, limit_blocks: int = 256) -> Json | None:
    """
    Fallback lookup for confirmed txs by scanning persisted blocks.

    Why this exists:
      - The status endpoint should not return "unknown" for a tx that is already
        committed in a block, even if tx_index rows are missing or delayed.
      - This keeps user-facing tx status usable while tx_index persistence is
        being hardened in the executor path.
    """
    mp = _safe_mempool(request)
    db = getattr(mp, "db", None)
    ex = _safe_executor(request)
    if db is None:
        return None

    want = str(tx_id or "").strip()
    if not want:
        return None

    chain_id = str(getattr(ex, "chain_id", "") or "").strip() or None

    try:
        with db.connection() as con:
            rows = con.execute(
                """
                SELECT height, block_id, block_json, created_ts_ms
                FROM blocks
                ORDER BY height DESC
                LIMIT ?;
                """,
                (int(limit_blocks),),
            ).fetchall()
    except Exception:
        return None

    for row in rows:
        try:
            height = int(row["height"])
            block_id = str(row["block_id"] or "")
            created_ts_ms = int(row["created_ts_ms"] or 0)
            block_json_raw = row["block_json"]
            block = (
                json.loads(block_json_raw) if isinstance(block_json_raw, str) else block_json_raw
            )
            if not isinstance(block, dict):
                continue

            header = block.get("header")
            header = header if isinstance(header, dict) else {}
            included_ts_ms = int(
                header.get("block_ts_ms") or block.get("block_ts_ms") or created_ts_ms or 0
            )

            # Preferred path: receipts contain tx_id.
            receipts = block.get("receipts")
            if isinstance(receipts, list):
                for receipt in receipts:
                    if not isinstance(receipt, dict):
                        continue
                    r_tx_id = str(receipt.get("tx_id") or "").strip()
                    if r_tx_id == want:
                        return {
                            "tx_id": want,
                            "height": height,
                            "block_id": block_id,
                            "tx_type": str(receipt.get("tx_type") or ""),
                            "signer": str(receipt.get("signer") or ""),
                            "included_ts_ms": included_ts_ms,
                        }

            # Fallback path: compute deterministic tx_id from tx envelopes.
            txs = block.get("txs")
            if isinstance(txs, list):
                for env in txs:
                    if not isinstance(env, dict):
                        continue
                    try:
                        have = compute_tx_id(env, chain_id=chain_id)
                    except Exception:
                        continue
                    if str(have or "").strip() != want:
                        continue
                    return {
                        "tx_id": want,
                        "height": height,
                        "block_id": block_id,
                        "tx_type": str(env.get("tx_type") or ""),
                        "signer": str(env.get("signer") or ""),
                        "included_ts_ms": included_ts_ms,
                    }
        except Exception:
            continue

    return None


def _http_requires_sig_by_default() -> bool:
    """Default HTTP policy: require cryptographic signatures in prod.

    In production, validator-facing/public HTTP must fail closed regardless of
    WEALL_SIGVERIFY overrides. Outside production, operators may opt in.
    """
    mode = _mode()
    override = os.environ.get("WEALL_SIGVERIFY")
    if mode == "prod":
        return True
    if override is None:
        return False
    return bool(str(override).strip() == "1")


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

    body = await _read_json_limited(
        request, max_bytes_env="WEALL_MAX_HTTP_TX_BYTES", default_max_bytes=256 * 1024
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "Body must be a tx envelope object", {})

    # Strict schema validation (envelope + known payloads). This is our main
    # backend/frontend contract guardrail.
    try:
        validate_tx_envelope(body)
    except ValidationError as ve:
        raise ApiError.bad_request(
            "invalid_tx",
            "tx envelope failed schema validation",
            {"errors": ve.errors()},
        )

    tx_type = str(body.get("tx_type") or "").strip()
    signer = str(body.get("signer") or "").strip()
    _validate_public_tx_chain_id(
        body=body, expected_chain_id=str(getattr(ex, "chain_id", "") or "")
    )

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

    # Signature enforcement at the HTTP boundary.
    if _http_requires_sig_by_default():
        if not isinstance(body.get("sig"), str) or not str(body.get("sig") or "").strip():
            raise ApiError.forbidden(
                "missing_sig",
                "signature is required for public tx submission",
                {"tx_type": tx_type, "signer": signer},
            )

        # Full cryptographic verification.
        if not verify_tx_signature(st, body):
            raise ApiError.forbidden(
                "bad_sig",
                "signature verification failed",
                {"tx_type": tx_type, "signer": signer},
            )

    # Compute deterministic id for idempotency (chain_id-aware).
    tx_id = compute_tx_id(body, chain_id=str(getattr(ex, "chain_id", "") or "").strip() or None)

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

    # Public /tx/submit must not become a local-only trap during multi-node devnet.
    # Mirror /mempool/submit gossip behavior after successful local admission.
    try:
        nn = _net_node(request)
        if nn is not None and out_tx_id:
            msg = nn.build_tx_envelope_msg(body, client_tx_id=out_tx_id)
            nn.gossip_announce_tx(msg)
    except Exception:
        pass

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

    mp = _safe_mempool(request)
    try:
        if bool(getattr(mp, "contains", lambda _t: False)(t)):
            return {"ok": True, "tx_id": t, "status": "pending"}
    except Exception:
        pass

    blk = _tx_block_lookup(request, t)
    if isinstance(blk, dict):
        return {
            "ok": True,
            "tx_id": t,
            "status": "confirmed",
            "height": int(blk.get("height") or 0),
            "block_id": str(blk.get("block_id") or ""),
            "included_ts_ms": int(blk.get("included_ts_ms") or 0),
            "tx_type": str(blk.get("tx_type") or ""),
            "signer": str(blk.get("signer") or ""),
        }

    return {"ok": True, "tx_id": t, "status": "unknown"}


_TX_INDEX_JSON_PATH = Path(__file__).resolve().parents[4] / "generated" / "tx_index.json"


def _load_tx_catalog_rows() -> list[Json]:
    try:
        raw = json.loads(_TX_INDEX_JSON_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []

    tx_types = raw.get("tx_types")
    if not isinstance(tx_types, list):
        return []

    rows: list[Json] = []
    for item in tx_types:
        if not isinstance(item, dict):
            continue
        gates = item.get("gates") if isinstance(item.get("gates"), dict) else {}
        tx_name = str(item.get("name") or item.get("tx_type") or "").strip()
        tx_origin = str(item.get("origin") or "").strip()
        tx_context = str(item.get("context") or "").strip()
        rows.append(
            {
                "id": str(item.get("id") or tx_name).strip(),
                "name": tx_name,
                "origin": tx_origin,
                "context": tx_context,
                "domain": str(item.get("domain") or "").strip(),
                "receipt_only": bool(item.get("receipt_only", False)),
                "subject_gate": str(item.get("subject_gate") or gates.get("subject_gate") or "").strip(),
                "api_entrypoints": _tx_public_entrypoints(tx_name, tx_origin, tx_context),
                "gates": gates,
            }
        )
    rows.sort(key=lambda row: (str(row.get("domain") or ""), str(row.get("name") or "")))
    return rows


def _count_by(rows: list[Json], key: str) -> list[Json]:
    counts: dict[str, int] = {}
    for row in rows:
        label = str(row.get(key) or "").strip() or "Unknown"
        counts[label] = int(counts.get(label, 0)) + 1
    return [
        {"name": name, "count": int(count)}
        for name, count in sorted(counts.items(), key=lambda item: (-int(item[1]), str(item[0]).lower()))
    ]


@router.get("/tx/catalog")
def tx_catalog(context: str | None = None, domain: str | None = None, search: str | None = None) -> Json:
    rows = _load_tx_catalog_rows()

    want_context = str(context or "").strip().lower()
    want_domain = str(domain or "").strip().lower()
    want_search = str(search or "").strip().lower()

    filtered: list[Json] = []
    for row in rows:
        row_context = str(row.get("context") or "").strip().lower()
        row_domain = str(row.get("domain") or "").strip().lower()
        row_name = str(row.get("name") or "").strip().lower()
        row_gate = str(row.get("subject_gate") or "").strip().lower()

        if want_context and row_context != want_context:
            continue
        if want_domain and row_domain != want_domain:
            continue
        if want_search and want_search not in row_name and want_search not in row_gate and want_search not in row_domain:
            continue
        filtered.append(row)

    return {
        "ok": True,
        "total": int(len(rows)),
        "count": int(len(filtered)),
        "filters": {
            "context": str(context or "").strip(),
            "domain": str(domain or "").strip(),
            "search": str(search or "").strip(),
        },
        "summary": {
            "by_context": _count_by(filtered, "context"),
            "by_domain": _count_by(filtered, "domain"),
        },
        "items": filtered,
    }
