from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _read_json_limited
from weall.net.relay import RelayConfig, RelayEnvelopeError, RelaySpool

router = APIRouter()

Json = dict[str, Any]


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    v = str(raw or "").strip().lower()
    if not v:
        return bool(default)
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    if _is_prod():
        raise RuntimeError(f"invalid_boolean_env:{name}")
    return bool(default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        s = str(raw or "").strip()
        return int(s) if s else int(default)
    except Exception as exc:
        if _is_prod():
            raise RuntimeError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _relay_enabled() -> bool:
    return _env_bool("WEALL_NET_RELAY_ENABLED", False)


def _executor(request: Request) -> Any:
    return getattr(request.app.state, "executor", None)


def _chain_id(request: Request) -> str:
    ex = _executor(request)
    have = str(getattr(ex, "chain_id", "") or "").strip()
    return have or str(os.environ.get("WEALL_CHAIN_ID", "") or "").strip()


def _schema_version(request: Request) -> str:
    ex = _executor(request)
    try:
        fn = getattr(ex, "_schema_version", None)
        if callable(fn):
            have = str(fn() or "").strip()
            if have:
                return have
    except Exception:
        pass
    return str(os.environ.get("WEALL_NET_SCHEMA_VERSION", "1") or "1").strip() or "1"


def _tx_index_hash(request: Request) -> str:
    ex = _executor(request)
    try:
        fn = getattr(ex, "tx_index_hash", None)
        if callable(fn):
            have = str(fn() or "").strip()
            if have:
                return have
    except Exception:
        pass
    return str(os.environ.get("WEALL_TX_INDEX_HASH", "") or "").strip()


def _relay_cfg(request: Request) -> RelayConfig:
    chain_id = _chain_id(request)
    schema_version = _schema_version(request)
    tx_index_hash = _tx_index_hash(request)
    if not chain_id or not tx_index_hash:
        raise ApiError.internal(
            "relay_not_ready",
            "relay cannot determine chain_id or tx_index_hash",
            {"chain_id_present": bool(chain_id), "tx_index_hash_present": bool(tx_index_hash)},
        )
    return RelayConfig(
        chain_id=chain_id,
        schema_version=schema_version,
        tx_index_hash=tx_index_hash,
        max_payload_bytes=max(1024, _env_int("WEALL_NET_RELAY_MAX_PAYLOAD_BYTES", 512 * 1024)),
        max_ttl_ms=max(1000, _env_int("WEALL_NET_RELAY_MAX_TTL_MS", 10 * 60 * 1000)),
        max_fetch_limit=max(1, _env_int("WEALL_NET_RELAY_FETCH_LIMIT", 100)),
        allow_broadcast_recipient=_env_bool("WEALL_NET_RELAY_ALLOW_BROADCAST", False),
        max_access_ttl_ms=max(1000, _env_int("WEALL_NET_RELAY_MAX_ACCESS_TTL_MS", 60 * 1000)),
        allow_unbound_recipient_fetch=(not _is_prod()) or _env_bool("WEALL_NET_RELAY_ALLOW_UNBOUND_FETCH", False),
    )


def _relay_spool(request: Request) -> RelaySpool:
    spool = getattr(request.app.state, "net_relay_spool", None)
    if isinstance(spool, RelaySpool):
        return spool
    path = str(os.environ.get("WEALL_NET_RELAY_DB", "./data/net_relay.sqlite") or "").strip()
    if not path:
        path = "./data/net_relay.sqlite"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    spool = RelaySpool(path)
    request.app.state.net_relay_spool = spool
    return spool


def _ensure_enabled() -> None:
    if not _relay_enabled():
        raise ApiError.not_found("not_found", "Not Found", {})


@router.get("/net/relay/status")
def v1_net_relay_status(request: Request) -> Json:
    _ensure_enabled()
    cfg = _relay_cfg(request)
    status = _relay_spool(request).status(include_recipients=not _is_prod())
    return {
        "ok": True,
        "enabled": True,
        "chain_id": cfg.chain_id,
        "schema_version": cfg.schema_version,
        "tx_index_hash": cfg.tx_index_hash,
        "limits": {
            "max_payload_bytes": int(cfg.max_payload_bytes),
            "max_ttl_ms": int(cfg.max_ttl_ms),
            "max_fetch_limit": int(cfg.max_fetch_limit),
            "allow_broadcast_recipient": bool(cfg.allow_broadcast_recipient),
        },
        "spool": status,
        "authority": "transport_only",
    }


@router.post("/net/relay/submit")
async def v1_net_relay_submit(request: Request) -> Json:
    _ensure_enabled()
    body = await _read_json_limited(
        request,
        max_bytes_env="WEALL_NET_RELAY_HTTP_MAX_BYTES",
        default_max_bytes=768 * 1024,
    )
    envelope = body.get("envelope") if isinstance(body, dict) and "envelope" in body else body
    try:
        result = _relay_spool(request).submit(envelope, cfg=_relay_cfg(request))
    except RelayEnvelopeError as exc:
        raise ApiError.bad_request(str(exc.code), "invalid relay envelope", {}) from exc
    return {"ok": True, "accepted": True, **result, "authority": "transport_only"}


@router.get("/net/relay/fetch")
def v1_net_relay_fetch_legacy(request: Request, recipient_peer_id: str, limit: int = 100) -> Json:
    """Legacy unsigned fetch retained only for non-production compatibility.

    Production fetch is POST-only and recipient-signed so a third party cannot
    read another node's mailbox by guessing its peer id.
    """
    _ensure_enabled()
    if _is_prod() and not _env_bool("WEALL_NET_RELAY_ALLOW_LEGACY_UNSIGNED_FETCH", False):
        raise ApiError.bad_request(
            "relay_fetch_requires_signed_request",
            "relay fetch requires a signed recipient request",
            {},
        )
    try:
        envelopes = _relay_spool(request).fetch(
            recipient_peer_id=str(recipient_peer_id or ""),
            cfg=_relay_cfg(request),
            limit=int(limit or 100),
        )
    except RelayEnvelopeError as exc:
        raise ApiError.bad_request(str(exc.code), "invalid relay fetch", {}) from exc
    return {
        "ok": True,
        "recipient_peer_id": str(recipient_peer_id or ""),
        "messages": list(envelopes),
        "count": len(envelopes),
        "authority": "transport_only",
        "legacy_unsigned_fetch": True,
    }


@router.post("/net/relay/fetch")
async def v1_net_relay_fetch(request: Request) -> Json:
    _ensure_enabled()
    body = await _read_json_limited(
        request,
        max_bytes_env="WEALL_NET_RELAY_HTTP_MAX_BYTES",
        default_max_bytes=128 * 1024,
    )
    access_request = body.get("access_request") if isinstance(body, dict) and "access_request" in body else body
    if not isinstance(access_request, dict):
        raise ApiError.bad_request("bad_request", "invalid relay fetch body", {})
    try:
        cfg = _relay_cfg(request)
        envelopes = _relay_spool(request).fetch_authorized(
            access_request=access_request,
            cfg=cfg,
            limit=int(access_request.get("limit") or cfg.max_fetch_limit),
        )
    except RelayEnvelopeError as exc:
        raise ApiError.bad_request(str(exc.code), "invalid relay fetch", {}) from exc
    return {
        "ok": True,
        "recipient_peer_id": str(access_request.get("recipient_peer_id") or ""),
        "messages": list(envelopes),
        "count": len(envelopes),
        "authority": "transport_only",
        "recipient_authenticated": True,
    }


@router.post("/net/relay/ack")
async def v1_net_relay_ack(request: Request) -> Json:
    _ensure_enabled()
    body = await _read_json_limited(
        request,
        max_bytes_env="WEALL_NET_RELAY_HTTP_MAX_BYTES",
        default_max_bytes=128 * 1024,
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "invalid relay ack body", {})
    access_request = body.get("access_request") if "access_request" in body else body
    if not isinstance(access_request, dict):
        raise ApiError.bad_request("bad_request", "invalid relay ack body", {})
    # Backward-compatible unsigned ACK is allowed only outside production.
    if "sig" not in access_request and not _is_prod():
        recipient = str(access_request.get("recipient_peer_id") or "").strip()
        relay_ids_raw = access_request.get("relay_ids")
        relay_ids = relay_ids_raw if isinstance(relay_ids_raw, list) else []
        try:
            deleted = _relay_spool(request).ack(
                recipient_peer_id=recipient,
                relay_ids=tuple(str(x or "").strip() for x in relay_ids),
            )
        except RelayEnvelopeError as exc:
            raise ApiError.bad_request(str(exc.code), "invalid relay ack", {}) from exc
        return {"ok": True, "acked": int(deleted), "authority": "transport_only", "legacy_unsigned_ack": True}
    try:
        deleted = _relay_spool(request).ack_authorized(
            access_request=access_request,
            cfg=_relay_cfg(request),
        )
    except RelayEnvelopeError as exc:
        raise ApiError.bad_request(str(exc.code), "invalid relay ack", {}) from exc
    return {"ok": True, "acked": int(deleted), "authority": "transport_only", "recipient_authenticated": True}
