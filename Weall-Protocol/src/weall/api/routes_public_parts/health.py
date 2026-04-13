from __future__ import annotations

import os
import time
from typing import Any

from fastapi import APIRouter, Request

from weall.runtime.econ_phase import econ_allowed_from_state, is_econ_unlocked
from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)
from weall.runtime.helper_status_endpoint_integration import (
    build_node_status_envelope,
    build_readyz_envelope,
)
from weall.runtime.helper_status_surface import build_helper_status_surface
from weall.runtime.runtime_authority import (
    authority_contract_from_lifecycle,
    startup_authority_contract_from_app_state,
)
from weall.runtime.node_runtime_config import resolve_node_runtime_config_from_env
from weall.runtime.protocol_profile import (
    runtime_clock_skew_warn_ms,
    runtime_max_block_future_drift_ms,
    runtime_protocol_profile_hash,
)

router = APIRouter()


class HealthRouteConfigError(ValueError):
    """Raised when explicit operator health/readiness envs are malformed in prod."""


class HealthTelemetryError(RuntimeError):
    """Raised when consensus/telemetry helpers return malformed data in prod."""


_ALLOWED_TRUE = {"1", "true", "yes", "y", "on"}
_ALLOWED_FALSE = {"0", "false", "no", "n", "off"}


def _is_prod() -> bool:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return False
    return (str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod") == "prod"


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    s = str(v or "").strip().lower()
    if not s:
        return bool(default)
    if s in _ALLOWED_TRUE:
        return True
    if s in _ALLOWED_FALSE:
        return False
    if _is_prod():
        raise HealthRouteConfigError(f"invalid_boolean_env:{name}")
    return bool(default)


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


def _try_executor_snapshot(ex: Any) -> dict[str, Any] | None:
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


def _try_tx_index_hash(ex: Any) -> str | None:
    if ex is None:
        return None
    fn = getattr(ex, "tx_index_hash", None)
    if callable(fn):
        try:
            return _safe_str(fn())
        except Exception:
            return None
    v = getattr(ex, "tx_index_hash", None)
    if isinstance(v, str) and v:
        return v
    return None


def _try_bft_diagnostics(ex: Any) -> dict[str, object]:
    if ex is None:
        return {
            "stalled": False,
            "stall_reason": "unknown",
            "pending_remote_blocks_count": 0,
            "pending_candidates_count": 0,
            "pending_missing_qcs_count": 0,
            "pending_fetch_requests_count": 0,
            "pending_artifacts_pruned": False,
            "pacemaker_timeout_ms": 0,
            "clock_skew_warning": False,
            "clock_skew_ahead_ms": 0,
            "protocol_profile_hash": runtime_protocol_profile_hash(),
            "reputation_scale": 0,
            "max_block_future_drift_ms": runtime_max_block_future_drift_ms(),
            "clock_skew_warn_ms": runtime_clock_skew_warn_ms(),
        }
    fn = getattr(ex, "bft_diagnostics", None)
    if callable(fn):
        try:
            out = fn()
            if not isinstance(out, dict):
                if _is_prod():
                    raise HealthTelemetryError("invalid_bft_diagnostics_shape")
            else:
                return {
                    "stalled": bool(out.get("stalled", False)),
                    "stall_reason": _safe_str(out.get("stall_reason"), "unknown"),
                    "pending_remote_blocks_count": _safe_int(out.get("pending_remote_blocks_count"), 0),
                    "pending_candidates_count": _safe_int(out.get("pending_candidates_count"), 0),
                    "pending_missing_qcs_count": _safe_int(out.get("pending_missing_qcs_count"), 0),
                    "pending_fetch_requests_count": _safe_int(out.get("pending_fetch_requests_count"), 0),
                    "pending_artifacts_pruned": bool(out.get("pending_artifacts_pruned", False)),
                    "pacemaker_timeout_ms": _safe_int(out.get("pacemaker_timeout_ms"), 0),
                    "clock_skew_warning": bool(out.get("clock_skew_warning", False)),
                    "clock_skew_ahead_ms": _safe_int(out.get("clock_skew_ahead_ms"), 0),
                    "protocol_profile_hash": _safe_str(out.get("protocol_profile_hash"), runtime_protocol_profile_hash()),
                    "reputation_scale": _safe_int(out.get("reputation_scale"), 0),
                    "max_block_future_drift_ms": _safe_int(out.get("max_block_future_drift_ms"), runtime_max_block_future_drift_ms()),
                    "clock_skew_warn_ms": _safe_int(out.get("clock_skew_warn_ms"), runtime_clock_skew_warn_ms()),
                }
        except Exception:
            if _is_prod():
                raise
    return {
        "stalled": False,
        "stall_reason": "unknown",
        "pending_remote_blocks_count": 0,
        "pending_candidates_count": 0,
        "pending_missing_qcs_count": 0,
        "pending_fetch_requests_count": 0,
        "pacemaker_timeout_ms": 0,
        "clock_skew_warning": False,
        "clock_skew_ahead_ms": 0,
        "protocol_profile_hash": runtime_protocol_profile_hash(),
        "reputation_scale": 0,
        "max_block_future_drift_ms": runtime_max_block_future_drift_ms(),
        "clock_skew_warn_ms": runtime_clock_skew_warn_ms(),
    }


def _try_executor_running_flag(ex: Any) -> bool | None:
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
    if ex is None:
        return {
            "running": None,
            "unhealthy": None,
            "last_error": None,
            "consecutive_failures": None,
        }

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


def _try_peer_counts(app_state: Any) -> dict[str, int | None]:
    connected_peers: int | None = None
    established_sessions: int | None = None

    net = getattr(app_state, "net_node", None)
    if net is None:
        net = getattr(app_state, "net", None)
    if net is None:
        return {"connected_peers": None, "established_sessions": None}

    try:
        t = getattr(net, "transport", None)
        if t is not None and hasattr(t, "connections"):
            conns = list(t.connections())  # type: ignore[call-arg]
            connected_peers = len(conns)
    except Exception:
        connected_peers = None

    try:
        peer_ids_fn = getattr(net, "peer_ids", None)
        sess_fn = getattr(net, "session_is_established", None)
        if callable(peer_ids_fn) and callable(sess_fn):
            ids = list(peer_ids_fn())
            established_sessions = sum(1 for pid in ids if bool(sess_fn(pid)))
    except Exception:
        established_sessions = None

    return {"connected_peers": connected_peers, "established_sessions": established_sessions}




def _node_lifecycle(request: Request) -> dict[str, Any]:
    ex = getattr(request.app.state, "executor", None)
    if ex is None:
        return {}
    fn = getattr(ex, "node_lifecycle_status", None)
    if callable(fn):
        try:
            out = fn()
            if isinstance(out, dict):
                return dict(out)
        except Exception:
            pass
    return {}


def _authority_contract(request: Request) -> tuple[dict[str, Any], str]:
    contract = startup_authority_contract_from_app_state(request.app.state)
    if isinstance(contract, dict) and contract:
        merged = dict(contract)
        merged.setdefault("contract_source", "app_startup")
        return merged, str(merged.get("contract_source") or "app_startup")

    lifecycle = _node_lifecycle(request)
    runtime_contract = authority_contract_from_lifecycle(lifecycle, source="runtime")
    return runtime_contract, str(runtime_contract.get("contract_source") or "runtime")

def _try_helper_release_gate_report(app_state: Any):
    try:
        return getattr(app_state, "helper_release_gate_report", None)
    except Exception:
        return None


def _helper_status_surface(request: Request, chain_id: str) -> Any:
    authority_contract, contract_source = _authority_contract(request)
    helper_requested = bool(authority_contract.get("helper_requested", resolve_node_runtime_config_from_env().helper_enabled_requested))
    helper_authority_known = any(
        authority_contract.get(key)
        for key in ("effective_state", "startup_action", "promotion_failure_reasons", "effective_roles")
    )
    status = evaluate_helper_startup(
        config=HelperStartupConfig(
            helper_mode_requested=helper_requested,
            helper_authority_ok=(not helper_requested) or (not helper_authority_known) or bool(authority_contract.get("helper_effective", False)),
            chain_id_ok=bool(chain_id),
            protocol_profile_ok=True,
            validator_set_ok=True,
            trusted_anchor_ok=True,
            sqlite_wal_ok=True,
        ),
        helper_release_gate=_try_helper_release_gate_report(request.app.state),
    )
    diagnostic = build_helper_operator_diagnostic(status=status)
    payload = build_helper_status_surface(diagnostic=diagnostic).to_json()
    payload["authority_contract"] = authority_contract
    payload["authority_contract_source"] = contract_source
    payload["helper_requested"] = helper_requested
    payload["helper_effective"] = bool(authority_contract.get("helper_effective", False))
    return payload


def _health_payload(request: Request) -> dict[str, object]:
    ex = getattr(request.app.state, "executor", None)
    st = _try_executor_snapshot(ex)

    chain_id = None
    node_id = None
    height = None
    tip = None

    econ_unlocked = None
    economics_enabled = None

    if isinstance(st, dict):
        chain_id = _safe_str(
            st.get("chain_id") or st.get("params", {}).get("chain_id")
            if isinstance(st.get("params"), dict)
            else st.get("chain_id")
        )
        node_id = _safe_str(
            st.get("node_id") or st.get("params", {}).get("node_id")
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

    net_enabled = _env_bool("WEALL_NET_ENABLED", True)
    peer_identity_required = _env_bool("WEALL_NET_REQUIRE_PEER_IDENTITY", True)

    tx_index_hash = _try_tx_index_hash(ex)
    executor_running = _try_executor_running_flag(ex)
    block_loop = _try_block_loop_status(ex)

    peers = _try_peer_counts(request.app.state)
    bft_diag = _try_bft_diagnostics(ex)
    helper_payload = _helper_status_surface(request, chain_id or "")

    payload = {
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
        "consensus_diagnostics": bft_diag,
    }
    from weall.runtime.helper_status_surface import HelperStatusSurface
    helper_surface = HelperStatusSurface(
        helper_startup=dict(helper_payload.get("helper_startup") or {}),
        helper_status=str(helper_payload.get("helper_status") or ""),
        helper_severity=str(helper_payload.get("helper_severity") or ""),
        helper_summary=str(helper_payload.get("helper_summary") or ""),
    )
    merged = build_node_status_envelope(
        chain_id=chain_id or "",
        base_ok=bool(payload["ok"]),
        base_mode="validator",
        helper_surface=helper_surface,
    ).to_json() | {k: v for k, v in payload.items() if k not in {"ok", "chain_id", "mode"}}
    merged["helper"] = helper_payload
    return merged


@router.get("/health")
def health(request: Request) -> dict[str, object]:
    return _health_payload(request)


def _ready_payload(request: Request) -> dict[str, object]:
    ex = getattr(request.app.state, "executor", None)
    st = _try_executor_snapshot(ex)

    chain_id = None
    height = None
    tip = None
    if isinstance(st, dict):
        chain_id = _safe_str(
            st.get("chain_id") or st.get("params", {}).get("chain_id")
            if isinstance(st.get("params"), dict)
            else st.get("chain_id")
        )
        height = _safe_int(st.get("height"), 0)
        tip = _safe_str(st.get("tip"), "")

    tx_index_hash = _try_tx_index_hash(ex)
    bft_diag = _try_bft_diagnostics(ex)

    ready = bool(chain_id) and bool(tx_index_hash)

    require_block_loop = _env_bool("WEALL_READYZ_REQUIRE_BLOCK_LOOP", False)
    bl = _try_block_loop_status(ex)
    if require_block_loop:
        ready = bool(ready) and (bl.get("running") is True) and (bl.get("unhealthy") is not True)

    helper_payload = _helper_status_surface(request, chain_id or "")
    from weall.runtime.helper_status_surface import HelperStatusSurface
    helper_surface = HelperStatusSurface(
        helper_startup=dict(helper_payload.get("helper_startup") or {}),
        helper_status=str(helper_payload.get("helper_status") or ""),
        helper_severity=str(helper_payload.get("helper_severity") or ""),
        helper_summary=str(helper_payload.get("helper_summary") or ""),
    )
    helper_ready = build_readyz_envelope(
        chain_id=chain_id or "",
        base_ready=bool(ready),
        helper_surface=helper_surface,
    ).to_json()

    return {
        "ok": bool(helper_ready.get("ready", False)),
        "service": "weall-node",
        "version": "v1",
        "ts_ms": _now_ms(),
        "chain_id": chain_id or None,
        "height": height,
        "tip": tip,
        "tx_index_hash": tx_index_hash,
        "require_block_loop": bool(require_block_loop),
        "block_loop": bl,
        "consensus_diagnostics": bft_diag,
        "helper_status": str(helper_ready.get("helper_status") or ""),
        "helper_severity": str(helper_ready.get("helper_severity") or ""),
        "helper_summary": str(helper_ready.get("helper_summary") or ""),
        "authority_contract": helper_payload.get("authority_contract", {}),
        "authority_contract_source": helper_payload.get("authority_contract_source", "runtime"),
    }


@router.get("/readyz")
def readyz(request: Request) -> dict[str, object]:
    return _ready_payload(request)


@router.get("/healthz")
def healthz(request: Request) -> dict[str, object]:
    return _health_payload(request)
