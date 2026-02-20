from __future__ import annotations

import os
from typing import Any, Dict, List

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.ledger.state import LedgerView

from weall.api.routes_public_parts.common import _executor, _mempool, _att_pool, _snapshot

router = APIRouter()

Json = Dict[str, Any]


def _env_str(name: str, default: str) -> str:
    v = str(os.environ.get(name, "") or "").strip()
    return v if v else str(default)


def _env_int(name: str, default: int) -> int:
    try:
        v = str(os.environ.get(name, "") or "").strip()
        return int(v) if v else int(default)
    except Exception:
        return int(default)


@router.get("/status")
def status(request: Request) -> Json:
    """
    Public node status summary.

    Mounted under /v1 by routes_public.py, so the full path is:
      GET /v1/status
    """
    ex = _executor(request)
    mp = _mempool(request)
    ap = _att_pool(request)

    st = _snapshot(request)
    if not isinstance(st, dict):
        raise ApiError.internal("bad_state", "executor state is not a dict", {})

    ledger = LedgerView.from_ledger(st)

    height = int(st.get("height") or 0)
    tip = str(st.get("tip") or "")
    chain_id = str(st.get("chain_id") or _env_str("WEALL_CHAIN_ID", "weall-dev"))
    node_id = str(getattr(ex, "node_id", "") or _env_str("WEALL_NODE_ID", "local-node"))

    mempool_size = int(getattr(mp, "size", lambda: 0)())
    att_pool_size = int(getattr(ap, "size", lambda: 0)())

    active_validators: List[str] = ledger.get_active_validator_set() or []
    active_validator_count = int(len(active_validators))

    return {
        "ok": True,
        "chain_id": chain_id,
        "node_id": node_id,
        "height": height,
        "tip": tip,
        "mempool_size": mempool_size,
        "attestation_pool_size": att_pool_size,
        "active_validator_count": active_validator_count,
        "mode": _env_str("WEALL_MODE", "prod"),
        "db_path": _env_str("WEALL_DB_PATH", "./data/weall.db"),
    }


@router.get("/chain/head")
def chain_head(request: Request) -> Json:
    """Return the current chain head summary.

    Mounted under /v1:
      GET /v1/chain/head
    """
    st = _snapshot(request)
    if not isinstance(st, dict):
        raise ApiError.internal("bad_state", "executor state is not a dict", {})

    height = int(st.get("height") or 0)
    tip = str(st.get("tip") or "")
    tip_hash = str(st.get("tip_hash") or "")
    tip_ts_ms = int(st.get("tip_ts_ms") or st.get("last_block_ts_ms") or 0)
    chain_id = str(st.get("chain_id") or _env_str("WEALL_CHAIN_ID", "weall-dev"))

    return {
        "ok": True,
        "chain_id": chain_id,
        "height": height,
        "tip": tip,
        "tip_hash": tip_hash,
        "tip_ts_ms": tip_ts_ms,
    }


@router.get("/status/mempool")
def status_mempool(request: Request) -> Json:
    """
    Debug endpoint: return recent mempool items.

    Mounted under /v1:
      GET /v1/status/mempool
    """
    mp = _mempool(request)

    limit = _env_int("WEALL_STATUS_MEMPOOL_LIMIT", 50)
    limit = max(1, min(int(limit), 500))

    try:
        items = mp.peek(limit=limit)
    except Exception:
        items = []

    trimmed = []
    for env in items:
        if not isinstance(env, dict):
            continue
        trimmed.append(
            {
                "tx_id": str(env.get("tx_id") or ""),
                "tx_type": str(env.get("tx_type") or ""),
                "signer": str(env.get("signer") or ""),
                "nonce": env.get("nonce", 0),
                "received_ms": env.get("received_ms", 0),
                "expires_ms": env.get("expires_ms", 0),
            }
        )

    return {"ok": True, "count": len(trimmed), "items": trimmed}


@router.get("/status/attestations")
def status_attestations(request: Request) -> Json:
    """
    Debug endpoint: return attestations for the current tip.

    Mounted under /v1:
      GET /v1/status/attestations
    """
    ap = _att_pool(request)

    st = _snapshot(request)
    tip = str(st.get("tip") or "")

    if not tip:
        return {"ok": True, "block_id": "", "count": 0, "items": []}

    limit = _env_int("WEALL_STATUS_ATTESTATIONS_LIMIT", 50)
    limit = max(1, min(int(limit), 500))

    try:
        items = ap.fetch_for_block(tip, limit=limit)
    except Exception:
        items = []

    trimmed = []
    for env in items:
        if not isinstance(env, dict):
            continue
        trimmed.append(
            {
                "att_id": str(env.get("att_id") or ""),
                "signer": str(env.get("signer") or ""),
                "block_id": str(env.get("block_id") or tip),
                "received_ms": env.get("received_ms", 0),
                "expires_ms": env.get("expires_ms", 0),
            }
        )

    return {"ok": True, "block_id": tip, "count": len(trimmed), "items": trimmed}


@router.get("/state/snapshot")
def state_snapshot(request: Request) -> Json:
    """
    Convenience endpoint: return the full ledger snapshot.

    Mounted under /v1:
      GET /v1/state/snapshot
    """
    st = _snapshot(request)
    if not isinstance(st, dict):
        raise ApiError.internal("bad_state", "state snapshot not a dict", {})
    return {"ok": True, "state": st}
