from __future__ import annotations

import math
import os
import time
from typing import Any, Mapping

from fastapi import APIRouter, Request

from weall.runtime.chain_config import load_chain_config, production_bootstrap_report
from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)
from weall.runtime.helper_status_route_adapter import build_api_status_response_shape
from weall.runtime.helper_status_surface import build_helper_status_surface
from weall.runtime.protocol_profile import (
    effective_runtime_consensus_posture,
    runtime_protocol_profile_hash,
    runtime_startup_fingerprint,
)

router = APIRouter()

_ALLOWED_TRUE = {"1", "true", "yes", "y", "on"}
_ALLOWED_FALSE = {"0", "false", "no", "n", "off"}


class StatusRouteConfigError(ValueError):
    """Raised when operator-facing status envs are malformed in prod."""


def _is_prod() -> bool:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return False
    return (str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod") == "prod"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    s = str(raw or "").strip().lower()
    if not s:
        return bool(default)
    if s in _ALLOWED_TRUE:
        return True
    if s in _ALLOWED_FALSE:
        return False
    if _is_prod():
        raise StatusRouteConfigError(f"invalid_boolean_env:{name}")
    return bool(default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception:
        if _is_prod():
            raise StatusRouteConfigError(f"invalid_integer_env:{name}")
        return int(default)


def _safe_str(v: Any, default: str = "") -> str:
    try:
        if v is None:
            return str(default)
        return str(v)
    except Exception:
        return str(default)


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or isinstance(v, bool):
            return int(default)
        return int(v)
    except Exception:
        return int(default)


def _safe_bool(v: Any, default: bool = False) -> bool:
    try:
        if v is None:
            return bool(default)
        return bool(v)
    except Exception:
        return bool(default)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _try_executor_snapshot(ex: Any) -> dict[str, Any] | None:
    if ex is None:
        return None
    snap = getattr(ex, "snapshot", None)
    if not callable(snap):
        return None
    try:
        out = snap()
        return out if isinstance(out, dict) else None
    except Exception:
        return None


def _try_read_state(ex: Any) -> dict[str, Any] | None:
    if ex is None:
        return None
    fn = getattr(ex, "read_state", None)
    if not callable(fn):
        return _try_executor_snapshot(ex)
    try:
        out = fn()
        return out if isinstance(out, dict) else None
    except Exception:
        return _try_executor_snapshot(ex)


def _tx_index_hash(ex: Any, state: Mapping[str, Any]) -> str:
    fn = getattr(ex, "tx_index_hash", None)
    if callable(fn):
        try:
            out = _safe_str(fn(), "")
            if out:
                return out
        except Exception:
            pass
    meta = state.get("meta")
    if isinstance(meta, dict):
        return _safe_str(meta.get("tx_index_hash"), "")
    return ""


def _schema_version(ex: Any, state: Mapping[str, Any]) -> str:
    meta = state.get("meta")
    if isinstance(meta, dict):
        out = _safe_str(meta.get("schema_version"), "")
        if out:
            return out
    cached = getattr(ex, "_schema_version_cached", None)
    return _safe_str(cached, "")


def _helper_release_gate_report(app_state: Any):
    try:
        return getattr(app_state, "helper_release_gate_report", None)
    except Exception:
        return None


def _helper_surface(request: Request, chain_id: str):
    status = evaluate_helper_startup(
        config=HelperStartupConfig(
            helper_mode_requested=_env_bool("WEALL_HELPER_MODE_ENABLED", False),
            chain_id_ok=bool(chain_id),
            protocol_profile_ok=True,
            validator_set_ok=True,
            trusted_anchor_ok=True,
            sqlite_wal_ok=True,
        ),
        helper_release_gate=_helper_release_gate_report(request.app.state),
    )
    diagnostic = build_helper_operator_diagnostic(status=status)
    return build_helper_status_surface(diagnostic=diagnostic)


def _peer_debug(app_state: Any) -> dict[str, Any]:
    net = getattr(app_state, "net_node", None)
    if net is None:
        net = getattr(app_state, "net", None)
    if net is None:
        return {
            "ok": True,
            "enabled": _env_bool("WEALL_NET_ENABLED", False),
            "counts": {},
            "peers": [],
        }
    fn = getattr(net, "peers_debug", None)
    if callable(fn):
        try:
            out = fn()
            if isinstance(out, dict):
                return out
        except Exception:
            pass
    return {
        "ok": True,
        "enabled": _env_bool("WEALL_NET_ENABLED", False),
        "counts": {},
        "peers": [],
    }


def _active_validators(state: Mapping[str, Any]) -> list[str]:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        return []
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        return []
    active = validators.get("active_set")
    if isinstance(active, list):
        out = []
        seen = set()
        for x in sorted(_safe_str(v, "") for v in active if _safe_str(v, "")):
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    return []


def _quorum_threshold(n: int) -> int:
    return int(math.ceil((2 * int(n)) / 3.0)) if n > 0 else 0


def _fault_tolerance(n: int) -> int:
    return max(0, (int(n) - 1) // 3)


def _current_leader(validators: list[str], view: int) -> str:
    if not validators:
        return ""
    return validators[int(view) % len(validators)]


def _next_leader(validators: list[str], view: int) -> str:
    if not validators:
        return ""
    return validators[(int(view) + 1) % len(validators)]


def _consensus_phase(state: Mapping[str, Any]) -> str:
    consensus = state.get("consensus")
    if isinstance(consensus, dict):
        phase = consensus.get("phase")
        if isinstance(phase, dict):
            return _safe_str(phase.get("current"), "")
    return ""


def _consensus_security_summary(state: Mapping[str, Any], validators: list[str]) -> dict[str, Any]:
    phase = _consensus_phase(state)
    n = len(validators)
    return {
        "public_bft_active": bool(phase == "bft_active" or n >= 4),
        "fault_tolerance": _fault_tolerance(n),
    }


def _consensus_diagnostics(ex: Any) -> dict[str, Any]:
    fn = getattr(ex, "bft_diagnostics", None)
    if callable(fn):
        try:
            out = fn()
            if isinstance(out, dict):
                return out
        except Exception:
            pass
    return {}



def _local_validator_lifecycle(state: Mapping[str, Any], validator_account: str) -> dict[str, Any]:
    validators_root = state.get("validators")
    registry = validators_root.get("registry") if isinstance(validators_root, dict) else None
    if not isinstance(registry, dict):
        registry = {}
    rec = registry.get(validator_account) if validator_account else None
    rec = rec if isinstance(rec, dict) else {}

    consensus = state.get("consensus")
    consensus = consensus if isinstance(consensus, dict) else {}
    epochs = consensus.get("epochs")
    epochs = epochs if isinstance(epochs, dict) else {}
    validator_set = consensus.get("validator_set")
    validator_set = validator_set if isinstance(validator_set, dict) else {}
    pending = validator_set.get("pending")
    pending = pending if isinstance(pending, dict) else {}

    current_epoch = _safe_int(epochs.get("current", validator_set.get("epoch", 0)), 0)
    current_set_hash = _safe_str(validator_set.get("set_hash"), "")
    active_validators = _active_validators(state)
    pending_active_set = pending.get("active_set") if isinstance(pending.get("active_set"), list) else []
    pending_activate_at_epoch = _safe_int(pending.get("activate_at_epoch"), 0)

    if validator_account and not rec:
        if validator_account in active_validators:
            lifecycle_state = "active"
        else:
            lifecycle_state = "observer"
    else:
        lifecycle_state = _safe_str(rec.get("status"), "observer") or "observer"
        if lifecycle_state == "active_validator":
            lifecycle_state = "active"

    pending_activation_epoch = _safe_int(
        rec.get("effective_epoch", rec.get("approved_activation_epoch", rec.get("requested_activation_epoch", 0))),
        0,
    )
    if validator_account and validator_account in pending_active_set and pending_activate_at_epoch > 0:
        pending_activation_epoch = pending_activate_at_epoch
        if lifecycle_state in {"candidate", "observer"}:
            lifecycle_state = "pending_activation"

    local_is_active = bool(validator_account and validator_account in active_validators and lifecycle_state not in {"removed", "suspended"})
    local_is_pending = bool(
        lifecycle_state == "pending_activation"
        or (
            validator_account
            and validator_account in pending_active_set
            and pending_activate_at_epoch > current_epoch
        )
    )

    if lifecycle_state == "observer" and local_is_pending:
        lifecycle_state = "pending_activation"
    if lifecycle_state == "observer" and local_is_active:
        lifecycle_state = "active"

    return {
        "validator_lifecycle_state": lifecycle_state,
        "local_validator_account": _safe_str(validator_account, ""),
        "local_validator_record_found": bool(validator_account and isinstance(rec, dict) and bool(rec)),
        "local_validator_pubkey": _safe_str(rec.get("pubkey"), ""),
        "local_validator_node_id": _safe_str(rec.get("node_id"), ""),
        "local_validator_is_active": local_is_active,
        "local_validator_is_pending": local_is_pending,
        "local_validator_is_suspended": lifecycle_state == "suspended",
        "local_validator_is_removed": lifecycle_state == "removed",
        "pending_activation_epoch": int(pending_activation_epoch) if pending_activation_epoch > 0 else None,
        "current_validator_epoch": current_epoch,
        "current_validator_set_hash": current_set_hash,
        "requested_activation_epoch": _safe_int(rec.get("requested_activation_epoch"), 0) or None,
        "approved_activation_epoch": _safe_int(rec.get("approved_activation_epoch"), 0) or None,
        "validator_registry_status": _safe_str(rec.get("status"), lifecycle_state),
        "validator_metadata_hash": _safe_str(rec.get("metadata_hash"), ""),
    }

def _runtime_profile_payload(diag: Mapping[str, Any]) -> dict[str, Any]:
    posture = effective_runtime_consensus_posture()
    return {
        "protocol_profile_hash": _safe_str(diag.get("protocol_profile_hash"), runtime_protocol_profile_hash()),
        "reputation_scale": _safe_int(diag.get("reputation_scale"), _safe_int(posture.get("reputation_scale"), 0)),
        "timestamp_rule": _safe_str(diag.get("timestamp_rule"), _safe_str(posture.get("timestamp_rule"), "")),
        "max_block_future_drift_ms": _safe_int(
            diag.get("max_block_future_drift_ms"),
            _safe_int(posture.get("max_block_future_drift_ms"), 0),
        ),
        "clock_skew_warn_ms": _safe_int(
            diag.get("clock_skew_warn_ms"),
            _safe_int(posture.get("clock_skew_warn_ms"), 0),
        ),
        "max_block_time_advance_ms": _safe_int(
            diag.get("max_block_time_advance_ms"),
            _safe_int(posture.get("max_block_time_advance_ms"), 0),
        ),
    }


def _startup_fingerprint(ex: Any, state: Mapping[str, Any], validator_account: str) -> dict[str, Any]:
    validators = _active_validators(state)
    current_epoch_fn = getattr(ex, "_current_validator_epoch", None)
    current_set_hash_fn = getattr(ex, "_current_validator_set_hash", None)
    try:
        validator_epoch = int(current_epoch_fn()) if callable(current_epoch_fn) else 0
    except Exception:
        validator_epoch = 0
    try:
        validator_set_hash = _safe_str(current_set_hash_fn(), "") if callable(current_set_hash_fn) else ""
    except Exception:
        validator_set_hash = ""
    return runtime_startup_fingerprint(
        chain_id=_safe_str(state.get("chain_id"), ""),
        node_id=_safe_str(getattr(ex, "node_id", None), validator_account),
        tx_index_hash=_tx_index_hash(ex, state),
        schema_version=_schema_version(ex, state),
        bft_enabled=_env_bool("WEALL_BFT_ENABLED", False),
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
    )


def _base_status_payload(request: Request) -> dict[str, Any]:
    ex = getattr(request.app.state, "executor", None)
    state = _try_read_state(ex) or _try_executor_snapshot(ex) or {}

    chain_id = _safe_str(state.get("chain_id") or os.environ.get("WEALL_CHAIN_ID"), "")
    node_id = _safe_str(
        state.get("node_id") or getattr(ex, "node_id", None) or os.environ.get("WEALL_NODE_ID"),
        "",
    )
    return {
        "ok": True,
        "service": "weall-node",
        "version": "v1",
        "ts_ms": _now_ms(),
        "chain_id": chain_id or None,
        "node_id": node_id or None,
        "mode": "validator",
        "height": _safe_int(state.get("height"), 0),
        "tip": _safe_str(state.get("tip"), ""),
    }


@router.get("/status")
def status(request: Request) -> dict[str, Any]:
    base = _base_status_payload(request)
    helper_surface = _helper_surface(request, _safe_str(base.get("chain_id"), ""))
    shape = build_api_status_response_shape(
        chain_id=_safe_str(base.get("chain_id"), ""),
        base_ok=bool(base.get("ok", False)),
        base_mode=_safe_str(base.get("mode"), "validator"),
        base_ready=True,
        base_status_payload=base,
        base_readyz_payload={"ready": True, "checks": ["status"]},
        helper_surface=helper_surface,
    ).to_json()
    return shape["status_payload"]


@router.get("/status/operator")
def status_operator(request: Request) -> dict[str, Any]:
    # Fail closed on malformed explicit prod debug env.
    _env_bool("WEALL_ENABLE_PUBLIC_DEBUG", False)

    ex = getattr(request.app.state, "executor", None)
    state = _try_read_state(ex) or _try_executor_snapshot(ex) or {}
    validators = _active_validators(state)
    diag = _consensus_diagnostics(ex)
    peer_debug = _peer_debug(request.app.state)
    helper_surface = _helper_surface(request, _safe_str(state.get("chain_id"), ""))

    base = _base_status_payload(request)
    shape = build_api_status_response_shape(
        chain_id=_safe_str(base.get("chain_id"), ""),
        base_ok=bool(base.get("ok", False)),
        base_mode=_safe_str(base.get("mode"), "validator"),
        base_ready=True,
        base_status_payload={**base, "operator_view": True},
        base_readyz_payload={"ready": True, "checks": ["status", "operator"]},
        helper_surface=helper_surface,
    ).to_json()
    payload = dict(shape["status_payload"])
    payload["db_path"] = _safe_str(os.environ.get("WEALL_DB_PATH"), "")
    payload["mempool_size"] = _safe_int(getattr(getattr(ex, "mempool", None), "size", lambda: 0)(), 0)
    payload["attestation_pool_size"] = _safe_int(getattr(getattr(ex, "attestation_pool", None), "size", lambda: 0)(), 0)
    payload["block_loop"] = {
        "running": _safe_bool(getattr(ex, "block_loop_running", None), False),
        "unhealthy": _safe_bool(getattr(ex, "block_loop_unhealthy", None), False),
        "last_error": _safe_str(getattr(ex, "block_loop_last_error", None), ""),
        "consecutive_failures": _safe_int(getattr(ex, "block_loop_consecutive_failures", None), 0),
    }
    payload["net"] = {
        "enabled": _env_bool("WEALL_NET_ENABLED", False),
        "peer_counts": dict(peer_debug.get("counts", {})) if isinstance(peer_debug.get("counts"), dict) else {},
        "peers": list(peer_debug.get("peers", [])) if isinstance(peer_debug.get("peers"), list) else [],
    }
    payload["consensus"] = {
        "bft_enabled": _env_bool("WEALL_BFT_ENABLED", False),
        "validator_account": _safe_str(os.environ.get("WEALL_VALIDATOR_ACCOUNT"), ""),
        "profile_enforced": bool(effective_runtime_consensus_posture().get("profile_enforced", False)),
        "qc_less_blocks_allowed": bool(effective_runtime_consensus_posture().get("qc_less_blocks_allowed", False)),
        "unsafe_autocommit": bool(effective_runtime_consensus_posture().get("unsafe_autocommit_allowed", False)),
        "sigverify_required": bool(effective_runtime_consensus_posture().get("sigverify_required", False)),
        "trusted_anchor_required": bool(effective_runtime_consensus_posture().get("trusted_anchor_required", False)),
        "effective_posture": effective_runtime_consensus_posture(),
        "stalled": bool(diag.get("stalled", False)),
        "stall_reason": _safe_str(diag.get("stall_reason"), ""),
        "timestamp_rule": _safe_str(diag.get("timestamp_rule"), _safe_str(effective_runtime_consensus_posture().get("timestamp_rule"), "")),
        "uses_wall_clock_future_guard": _safe_bool(diag.get("uses_wall_clock_future_guard"), False),
    }
    payload["runtime_profile"] = _runtime_profile_payload(diag)
    payload["startup_fingerprint"] = _startup_fingerprint(
        ex,
        state,
        _safe_str(os.environ.get("WEALL_VALIDATOR_ACCOUNT"), ""),
    )
    try:
        cfg = load_chain_config()
        payload["bootstrap"] = production_bootstrap_report(cfg)
    except Exception:
        payload["bootstrap"] = {
            "ok": False,
            "observer_first_recommended": True,
            "recommended_join_mode": "observer_first_then_verify_then_enable_bft_signing",
        }
    payload["operator"] = {
        "helper_status": payload["helper"]["helper_status"],
        "helper_severity": payload["helper"]["helper_severity"],
        "helper_summary": payload["helper"]["helper_summary"],
        **_local_validator_lifecycle(state, _safe_str(os.environ.get("WEALL_VALIDATOR_ACCOUNT"), "")),
        "signing_enabled_locally": bool(payload.get("startup_fingerprint", {}).get("mode") or True),
        "signing_allowed_by_consensus_state": bool(getattr(ex, "validator_signing_enabled", lambda: False)()),
        "signing_block_reason": _safe_str(getattr(ex, "_effective_signing_block_reason", lambda: "")(), ""),
    }
    return payload


@router.get("/status/consensus")
def status_consensus(request: Request) -> dict[str, Any]:
    ex = getattr(request.app.state, "executor", None)
    state = _try_read_state(ex) or _try_executor_snapshot(ex) or {}
    validators = _active_validators(state)
    diag = _consensus_diagnostics(ex)
    peer_debug = _peer_debug(request.app.state)
    view = _safe_int(diag.get("view"), _safe_int(state.get("bft", {}).get("view") if isinstance(state.get("bft"), dict) else 0, 0))
    high_qc = state.get("bft", {}).get("high_qc") if isinstance(state.get("bft"), dict) else {}
    locked_qc = state.get("bft", {}).get("locked_qc") if isinstance(state.get("bft"), dict) else {}
    validator_account = _safe_str(os.environ.get("WEALL_VALIDATOR_ACCOUNT"), "")
    chain_id = _safe_str(state.get("chain_id"), "")
    current = _current_leader(validators, view)
    nxt = _next_leader(validators, view)
    startup = _startup_fingerprint(ex, state, validator_account)
    return {
        "ok": True,
        "chain_id": chain_id,
        "node_id": _safe_str(getattr(ex, "node_id", None), validator_account),
        "height": _safe_int(state.get("height"), 0),
        "tip": _safe_str(state.get("tip"), ""),
        "finalized_height": _safe_int((state.get("finalized") or {}).get("height") if isinstance(state.get("finalized"), dict) else 0, 0),
        "active_validator_count": len(validators),
        "quorum_threshold": _quorum_threshold(len(validators)),
        "view": view,
        "current_leader": current,
        "next_leader": nxt,
        "local_is_active_validator": validator_account in validators if validator_account else False,
        "local_is_expected_leader": bool(validator_account and validator_account == current),
        **_local_validator_lifecycle(state, validator_account),
        "high_qc": {
            "block_id": _safe_str((high_qc or {}).get("block_id"), _safe_str(diag.get("high_qc_id"), "")),
            "vote_count": len((high_qc or {}).get("votes", [])) if isinstance((high_qc or {}).get("votes"), list) else 0,
        },
        "locked_qc": {
            "block_id": _safe_str((locked_qc or {}).get("block_id"), _safe_str(diag.get("locked_qc_id"), "")),
            "vote_count": len((locked_qc or {}).get("votes", [])) if isinstance((locked_qc or {}).get("votes"), list) else 0,
        },
        "peer_counts": dict(peer_debug.get("counts", {})) if isinstance(peer_debug.get("counts"), dict) else {},
        "tx_index_hash": _tx_index_hash(ex, state),
        "startup_fingerprint": startup,
        "diagnostics": diag,
        "runtime_profile": _runtime_profile_payload(diag),
        "consensus_phase": _consensus_phase(state),
        "security_summary": _consensus_security_summary(state, validators),
    }


@router.get("/status/consensus/forensics")
def status_consensus_forensics(request: Request) -> dict[str, Any]:
    ex = getattr(request.app.state, "executor", None)
    fn = getattr(ex, "bft_operator_forensics", None)
    if callable(fn):
        out = fn()
        if isinstance(out, dict):
            return out
    diag = _consensus_diagnostics(ex)
    return {
        "ok": True,
        "chain_id": _safe_str(getattr(ex, "chain_id", None), ""),
        "node_id": _safe_str(getattr(ex, "node_id", None), ""),
        "diagnostics": diag,
        "recent_rejection_summary": dict(diag.get("recent_rejection_summary", {})) if isinstance(diag.get("recent_rejection_summary"), dict) else {},
        "pending_fetch_request_descriptors": list(diag.get("pending_fetch_request_descriptors", [])) if isinstance(diag.get("pending_fetch_request_descriptors"), list) else [],
        "pending_outbound_messages": list(diag.get("pending_outbound_messages", [])) if isinstance(diag.get("pending_outbound_messages"), list) else [],
        "journal_tail": list(diag.get("journal_tail", [])) if isinstance(diag.get("journal_tail"), list) else [],
    }


@router.get("/status/mempool")
def status_mempool(request: Request) -> dict[str, Any]:
    limit = _env_int("WEALL_STATUS_MEMPOOL_LIMIT", 50)
    ex = getattr(request.app.state, "executor", None)
    mp = getattr(ex, "mempool", None)
    items = []
    if mp is not None:
        peek = getattr(mp, "peek", None)
        if callable(peek):
            try:
                out = peek(limit=limit)
                if isinstance(out, list):
                    items = out
            except Exception:
                items = []
    return {
        "ok": True,
        "limit": limit,
        "size": _safe_int(getattr(mp, "size", lambda: 0)(), 0) if mp is not None else 0,
        "items": items,
    }


@router.get("/status/attestations")
def status_attestations(request: Request) -> dict[str, Any]:
    ex = getattr(request.app.state, "executor", None)
    ap = getattr(ex, "attestation_pool", None)
    return {
        "ok": True,
        "size": _safe_int(getattr(ap, "size", lambda: 0)(), 0) if ap is not None else 0,
    }


@router.get("/chain/head")
def chain_head(request: Request) -> dict[str, Any]:
    ex = getattr(request.app.state, "executor", None)
    state = _try_read_state(ex) or _try_executor_snapshot(ex) or {}
    return {
        "ok": True,
        "chain_id": _safe_str(state.get("chain_id"), ""),
        "height": _safe_int(state.get("height"), 0),
        "tip": _safe_str(state.get("tip"), ""),
    }
