from __future__ import annotations

import os
import time
from typing import Any, Optional

from fastapi import APIRouter, Request

from weall.runtime.econ_phase import econ_allowed_from_state, is_econ_unlocked

router = APIRouter()


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return int(default)
        if isinstance(v, bool):
            return int(default)
        return int(v)
    except Exception:
        return int(default)


def _safe_str(v: Any, default: str = "") -> str:
    try:
        if v is None:
            return str(default)
        s = str(v)
        return s
    except Exception:
        return str(default)


def _try_executor_snapshot(ex: Any) -> Optional[dict[str, Any]]:
    if ex is None:
        return None
    snap = getattr(ex, "snapshot", None)
    if not callable(snap):
        return None
    try:
        st = snap()
        return st if isinstance(st, dict) else None
    except Exception:
        return None


def _try_tx_index_hash(ex: Any) -> Optional[str]:
    if ex is None:
        return None
    fn = getattr(ex, "tx_index_hash", None)
    if callable(fn):
        try:
            return _safe_str(fn())
        except Exception:
            return None
    # fallback: some builds store it as a field
    v = getattr(ex, "tx_index_hash", None)
    if isinstance(v, str) and v:
        return v
    return None


def _try_executor_running_flag(ex: Any) -> Optional[bool]:
    """
    Best-effort: many executors keep a boolean like:
      - _running
      - running
      - is_running
      - block_loop_running
    We probe common names. If none exist, return None.
    """
    if ex is None:
        return None

    for name in ("_running", "running", "is_running", "block_loop_running", "_block_loop_running"):
        try:
            v = getattr(ex, name)
        except Exception:
            continue
        if isinstance(v, bool):
            return v
        if callable(v):
            try:
                out = v()
                if isinstance(out, bool):
                    return out
            except Exception:
                continue
    return None


def _try_block_loop_status(ex: Any) -> dict[str, object]:
    """Best-effort producer loop status.

    Populated by runtime.block_loop.BlockProducerLoop if used.
    """
    if ex is None:
        return {"running": None, "unhealthy": None, "last_error": None, "consecutive_failures": None}

    def _get(name: str):
        try:
            return getattr(ex, name)
        except Exception:
            return None

    running = _get("block_loop_running")
    unhealthy = _get("block_loop_unhealthy")
    last_error = _get("block_loop_last_error")
    consecutive = _get("block_loop_consecutive_failures")

    return {
        "running": running if isinstance(running, bool) else None,
        "unhealthy": unhealthy if isinstance(unhealthy, bool) else None,
        "last_error": _safe_str(last_error, "") if last_error is not None else None,
        "consecutive_failures": _safe_int(consecutive, 0) if consecutive is not None else None,
    }


def _try_peer_counts(app_state: Any) -> dict[str, Optional[int]]:
    """
    Best-effort: if the node has a net layer attached to app.state, expose:
      - connected_peers
      - established_sessions (handshake done)
    """
    connected_peers: Optional[int] = None
    established_sessions: Optional[int] = None

    net = getattr(app_state, "net_node", None)
    if net is None:
        net = getattr(app_state, "net", None)
    if net is None:
        return {"connected_peers": None, "established_sessions": None}

    # connected peers from transport
    try:
        t = getattr(net, "transport", None)
        if t is not None and hasattr(t, "connections"):
            conns = list(t.connections())  # type: ignore[call-arg]
            connected_peers = len(conns)
    except Exception:
        connected_peers = None

    # established sessions: try net.session_is_established(peer_id)
    try:
        peer_ids_fn = getattr(net, "peer_ids", None)
        sess_fn = getattr(net, "session_is_established", None)
        if callable(peer_ids_fn) and callable(sess_fn):
            ids = list(peer_ids_fn())
            established_sessions = sum(1 for pid in ids if bool(sess_fn(pid)))
    except Exception:
        established_sessions = None

    return {"connected_peers": connected_peers, "established_sessions": established_sessions}


def _health_payload(request: Request) -> dict[str, object]:
    # health must never crash — best-effort telemetry only
    ex = getattr(request.app.state, "executor", None)
    st = _try_executor_snapshot(ex)

    # Prefer chain_id/node_id from state snapshot if present, otherwise env.
    chain_id = None
    node_id = None
    height = None
    tip = None

    econ_unlocked = None
    economics_enabled = None

    if isinstance(st, dict):
        chain_id = _safe_str(
            st.get("chain_id")
            or st.get("params", {}).get("chain_id")
            if isinstance(st.get("params"), dict)
            else st.get("chain_id")
        )
        node_id = _safe_str(
            st.get("node_id")
            or st.get("params", {}).get("node_id")
            if isinstance(st.get("params"), dict)
            else st.get("node_id")
        )
        height = _safe_int(st.get("height"), 0)
        tip = _safe_str(st.get("tip"), "")
        try:
            econ_unlocked = bool(is_econ_unlocked(st))
            economics_enabled = bool(econ_allowed_from_state(st))
        except Exception:
            econ_unlocked = None
            economics_enabled = None

    if not chain_id:
        chain_id = _safe_str(os.environ.get("WEALL_CHAIN_ID"), "")
    if not node_id:
        node_id = _safe_str(os.environ.get("WEALL_NODE_ID"), "")

    # net flags
    net_enabled = _env_bool("WEALL_NET_ENABLED", True)
    peer_identity_required = _env_bool("WEALL_NET_REQUIRE_PEER_IDENTITY", True)

    # richer runtime fields
    tx_index_hash = _try_tx_index_hash(ex)
    executor_running = _try_executor_running_flag(ex)
    block_loop = _try_block_loop_status(ex)

    peers = _try_peer_counts(request.app.state)

    return {
        "ok": True,
        "service": "weall-node",
        "version": "v1",
        "ts_ms": _now_ms(),
        "chain_id": chain_id or None,
        "node_id": node_id or None,
        "height": height,
        "tip": tip,
        "tx_index_hash": tx_index_hash,
        "executor": {
            "running": executor_running,
            "block_loop": block_loop,
        },
        "economics": {
            "unlocked": econ_unlocked,
            "enabled": economics_enabled,
        },
        "net": {
            "enabled": net_enabled,
            "peer_identity_required": peer_identity_required,
            "connected_peers": peers["connected_peers"],
            "established_sessions": peers["established_sessions"],
        },
    }


@router.get("/v1/health")
def v1_health(request: Request) -> dict[str, object]:
    return _health_payload(request)


@router.get("/health")
def health(request: Request) -> dict[str, object]:
    # unversioned alias for ops tooling
    return _health_payload(request)


def _ready_payload(request: Request) -> dict[str, object]:
    """Readiness check.

    Intended for load balancers and webfront node selection.

    Policy:
      - must never crash
      - returns ok=true only if we can safely serve public API
      - includes chain_id, height, tip, tx_index_hash for client validation
    """
    ex = getattr(request.app.state, "executor", None)
    st = _try_executor_snapshot(ex)

    chain_id = None
    height = None
    tip = None
    if isinstance(st, dict):
        chain_id = _safe_str(
            st.get("chain_id")
            or st.get("params", {}).get("chain_id")
            if isinstance(st.get("params"), dict)
            else st.get("chain_id")
        )
        height = _safe_int(st.get("height"), 0)
        tip = _safe_str(st.get("tip"), "")

    tx_index_hash = _try_tx_index_hash(ex)

    # Minimal readiness: we must have a chain_id and tx_index_hash (prevents accidental cross-chain).
    ready = bool(chain_id) and bool(tx_index_hash)

    # Optional: require the block producer loop to be healthy/running.
    # Default is False so API-only deployments are still "ready".
    require_block_loop = _env_bool("WEALL_READYZ_REQUIRE_BLOCK_LOOP", False)
    bl = _try_block_loop_status(ex)
    if require_block_loop:
        ready = bool(ready) and (bl.get("running") is True) and (bl.get("unhealthy") is not True)

    return {
        "ok": bool(ready),
        "service": "weall-node",
        "version": "v1",
        "ts_ms": _now_ms(),
        "chain_id": chain_id or None,
        "height": height,
        "tip": tip,
        "tx_index_hash": tx_index_hash,
        "require_block_loop": bool(require_block_loop),
        "block_loop": bl,
    }


@router.get("/readyz")
def readyz(request: Request) -> dict[str, object]:
    return _ready_payload(request)


@router.get("/healthz")
def healthz(request: Request) -> dict[str, object]:
    # Kubernetes-style alias
    return _health_payload(request)
