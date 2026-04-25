# src/weall/api/routes_public_parts/state.py
from __future__ import annotations

import os
import uuid
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.runtime.executor import ExecutorError

router = APIRouter()

Json = dict[str, Any]


def _executor(request: Request) -> Any:
    ex = getattr(request.app.state, "executor", None)
    if ex is None:
        raise HTTPException(
            status_code=503, detail={"code": "not_ready", "message": "executor not ready"}
        )
    return ex


def _as_bool_env(name: str, default: bool = False) -> bool:
    raw = str(os.environ.get(name) or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE") or "").strip().lower()


def _sync_request_routes_enabled() -> bool:
    # State-sync request is read-only, but it can expose snapshots. Keep it on in
    # dev by default for controlled devnet harnesses and require an explicit flag
    # for production-like deployments.
    if _mode() == "prod":
        return _as_bool_env("WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE", False)
    return _as_bool_env("WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE", True)


def _sync_apply_routes_enabled() -> bool:
    # Applying remote state mutates local canonical state. It is only exposed for
    # controlled devnet/operator harnesses and remains fail-closed by default in
    # production.
    if _mode() == "prod":
        return _as_bool_env("WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE", False)
    return _as_bool_env("WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE", False)


def _message_type_value(value: Any) -> str:
    if isinstance(value, MsgType):
        return str(value.value)
    text = str(value or "").strip()
    if text.startswith("MsgType."):
        return text.split(".", 1)[1]
    return text


def _header_to_json(header: WireHeader) -> Json:
    return {
        "type": _message_type_value(header.type),
        "chain_id": str(header.chain_id or ""),
        "schema_version": str(header.schema_version or ""),
        "tx_index_hash": str(header.tx_index_hash or ""),
        "sent_ts_ms": header.sent_ts_ms,
        "corr_id": header.corr_id,
    }


def _header_from_json(raw: Any, *, expected_type: MsgType | None = None) -> WireHeader:
    if not isinstance(raw, dict):
        raise ValueError("header_not_object")
    typ_raw = _message_type_value(raw.get("type"))
    try:
        typ = MsgType(typ_raw)
    except Exception as exc:
        # Some serializers emit enum names rather than values.
        try:
            typ = MsgType[typ_raw]
        except Exception as exc2:  # noqa: BLE001 - normalized API error below
            raise ValueError("bad_header_type") from exc2
    if expected_type is not None and typ != expected_type:
        raise ValueError("bad_header_expected_type")
    sent = raw.get("sent_ts_ms")
    try:
        sent_i = int(sent) if sent is not None else None
    except Exception as exc:
        raise ValueError("bad_header_sent_ts_ms") from exc
    return WireHeader(
        type=typ,
        chain_id=str(raw.get("chain_id") or ""),
        schema_version=str(raw.get("schema_version") or ""),
        tx_index_hash=str(raw.get("tx_index_hash") or ""),
        sent_ts_ms=sent_i,
        corr_id=str(raw.get("corr_id") or "") or None,
    )


def _sync_response_to_json(resp: StateSyncResponseMsg) -> Json:
    return {
        "header": _header_to_json(resp.header),
        "ok": bool(resp.ok),
        "reason": resp.reason,
        "height": int(resp.height or 0),
        "snapshot": resp.snapshot,
        "snapshot_hash": resp.snapshot_hash,
        "snapshot_anchor": resp.snapshot_anchor,
        "blocks": list(resp.blocks or ()),
    }


def _sync_response_from_json(raw: Any) -> StateSyncResponseMsg:
    if not isinstance(raw, dict):
        raise ValueError("response_not_object")
    header = _header_from_json(raw.get("header"), expected_type=MsgType.STATE_SYNC_RESPONSE)
    blocks = raw.get("blocks") or ()
    if not isinstance(blocks, (list, tuple)):
        raise ValueError("response_blocks_not_sequence")
    snapshot = raw.get("snapshot")
    if snapshot is not None and not isinstance(snapshot, dict):
        raise ValueError("response_snapshot_not_object")
    anchor = raw.get("snapshot_anchor")
    if anchor is not None and not isinstance(anchor, dict):
        raise ValueError("response_snapshot_anchor_not_object")
    try:
        height = int(raw.get("height") or 0)
    except Exception as exc:
        raise ValueError("response_bad_height") from exc
    return StateSyncResponseMsg(
        header=header,
        ok=bool(raw.get("ok")),
        reason=str(raw.get("reason") or "") or None,
        height=height,
        snapshot=snapshot,
        snapshot_hash=str(raw.get("snapshot_hash") or "") or None,
        snapshot_anchor=anchor,
        blocks=tuple(dict(b) for b in blocks if isinstance(b, dict)),
    )


def _executor_tx_index_hash(ex: Any) -> str:
    """Return the executor tx-index hash without stringifying a bound method.

    ``WeAllExecutor.tx_index_hash`` is a method. The HTTP state-sync adapter
    must send the real digest in the request header, not the string
    representation of the bound method object.
    """

    fn = getattr(ex, "tx_index_hash", None)
    if callable(fn):
        try:
            return str(fn() or "").strip()
        except TypeError:
            pass
    return str(getattr(ex, "_tx_index_hash", "") or fn or "").strip()


def _executor_schema_version(ex: Any) -> str:
    fn = getattr(ex, "schema_version", None)
    if callable(fn):
        try:
            return str(fn() or "1").strip() or "1"
        except TypeError:
            pass
    return str(getattr(ex, "_schema_version_cached", "") or getattr(ex, "schema_version", "") or "1").strip() or "1"


def _executor_wire_header(ex: Any, msg_type: MsgType, *, corr_id: str | None = None) -> WireHeader:
    chain_id = str(getattr(ex, "chain_id", "") or "")
    schema_version = _executor_schema_version(ex)
    tx_index_hash = _executor_tx_index_hash(ex)
    if not chain_id or not tx_index_hash:
        raise HTTPException(
            status_code=503,
            detail={"code": "not_ready", "message": "executor chain identity incomplete"},
        )
    return WireHeader(
        type=msg_type,
        chain_id=chain_id,
        schema_version=schema_version,
        tx_index_hash=tx_index_hash,
        sent_ts_ms=None,
        corr_id=corr_id or f"sync:{uuid.uuid4().hex}",
    )


@router.get("/state/snapshot")
def state_snapshot(request: Request) -> Json:
    """Return the node's current ledger snapshot.

    This is a public debugging/UX endpoint used by the web front.

    Production note:
      - This endpoint can grow large over time.
      - Operators may disable it at the edge or replace it with a pruned view.
    """

    ex = _executor(request)
    st = ex.snapshot()
    if not isinstance(st, dict):
        return {"ok": False, "error": {"code": "bad_state", "message": "snapshot not a dict"}}

    # Keep response shape stable.
    return {"ok": True, "state": st}


@router.get("/state/block/{block_id}")
def state_block(block_id: str, request: Request) -> Json:
    ex = _executor(request)
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


@router.post("/sync/request")
async def state_sync_request(request: Request) -> Json:
    """Return a bounded state-sync response for a controlled peer.

    The response is the same protocol object used by the transport state-sync
    service, rendered as JSON so scripts can test join/catch-up without relying
    on a long-running P2P mesh during early controlled-devnet onboarding.
    """

    if not _sync_request_routes_enabled():
        raise HTTPException(
            status_code=403,
            detail={"code": "disabled", "message": "HTTP state-sync request route disabled"},
        )
    ex = _executor(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "body"})
    mode = str(body.get("mode") or "delta").strip().lower()
    if mode not in {"delta", "snapshot"}:
        raise HTTPException(
            status_code=400, detail={"code": "bad_request", "message": "bad sync mode"}
        )
    selector = body.get("selector")
    if selector is not None and not isinstance(selector, dict):
        raise HTTPException(
            status_code=400, detail={"code": "bad_request", "message": "selector"}
        )
    try:
        from_height = int(body.get("from_height") or 0)
        raw_to_height = body.get("to_height")
        to_height = int(raw_to_height) if raw_to_height is not None else None
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail={"code": "bad_request", "message": "height"}
        ) from exc

    req_msg = StateSyncRequestMsg(
        header=_executor_wire_header(
            ex, MsgType.STATE_SYNC_REQUEST, corr_id=str(body.get("corr_id") or "") or None
        ),
        mode=mode,  # type: ignore[arg-type]
        from_height=from_height,
        to_height=to_height,
        selector=selector,
    )
    svc_fn = getattr(ex, "_state_sync_service", None)
    if not callable(svc_fn):
        raise HTTPException(
            status_code=501, detail={"code": "not_supported", "message": "sync service unavailable"}
        )
    try:
        resp = svc_fn().handle_request(req_msg)
    except Exception as exc:  # noqa: BLE001 - API diagnostic path
        raise HTTPException(
            status_code=500, detail={"code": "sync_request_failed", "message": str(exc)}
        ) from exc
    return {"ok": bool(resp.ok), "response": _sync_response_to_json(resp)}


@router.post("/sync/apply")
async def state_sync_apply(request: Request) -> Json:
    """Apply a verified state-sync response to this node.

    This route is intentionally disabled unless the controlled-devnet sync apply
    flag is set. It still uses executor/state-sync verification and refuses
    trust-sensitive snapshot replacement unless the caller explicitly opts in.
    """

    if not _sync_apply_routes_enabled():
        raise HTTPException(
            status_code=403,
            detail={"code": "disabled", "message": "HTTP state-sync apply route disabled"},
        )
    ex = _executor(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "body"})
    try:
        resp = _sync_response_from_json(body.get("response"))
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail={"code": "bad_sync_response", "message": str(exc)}
        ) from exc
    trusted_anchor = body.get("trusted_anchor")
    if trusted_anchor is not None and not isinstance(trusted_anchor, dict):
        raise HTTPException(
            status_code=400, detail={"code": "bad_request", "message": "trusted_anchor"}
        )
    allow_snapshot = bool(body.get("allow_snapshot_bootstrap"))
    try:
        metas = ex.apply_state_sync_response(
            resp, trusted_anchor=trusted_anchor, allow_snapshot_bootstrap=allow_snapshot
        )
    except ExecutorError as exc:
        raise HTTPException(
            status_code=409, detail={"code": "state_sync_apply_failed", "message": str(exc)}
        ) from exc
    except Exception as exc:  # noqa: BLE001 - API diagnostic path
        raise HTTPException(
            status_code=500, detail={"code": "state_sync_apply_failed", "message": str(exc)}
        ) from exc
    return {
        "ok": True,
        "applied_count": len(metas),
        "metas": [asdict(m) for m in metas],
        "height": int((ex.snapshot() or {}).get("height") or 0),
    }
