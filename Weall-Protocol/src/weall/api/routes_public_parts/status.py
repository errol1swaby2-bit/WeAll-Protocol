from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request

from weall.api.routes_public_parts.common import _att_pool, _executor, _mempool, _snapshot
from weall.ledger.state import LedgerView
from weall.runtime.chain_config import load_chain_config, production_bootstrap_report
from weall.runtime.bft_hotstuff import consensus_contract_summary, consensus_security_summary, leader_for_view, normalize_consensus_phase, quorum_threshold
from weall.runtime.metrics import metrics_enabled
from weall.runtime.protocol_profile import (
    effective_runtime_consensus_posture,
    runtime_clock_skew_warn_ms,
    runtime_max_block_future_drift_ms,
    runtime_protocol_profile_hash,
    runtime_startup_fingerprint,
)

router = APIRouter()

Json = Dict[str, Any]


class StatusEndpointConfigError(RuntimeError):
    """Raised when operator-supplied status endpoint config is malformed in prod."""


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def _env_str(name: str, default: str) -> str:
    v = str(os.environ.get(name, "") or "").strip()
    return v if v else str(default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        v = str(raw or "").strip()
        return int(v) if v else int(default)
    except Exception as exc:
        if _is_prod():
            raise StatusEndpointConfigError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    v = str(raw or "").strip()
    if v == "":
        return bool(default)
    vl = v.lower()
    if vl in {"1", "true", "yes", "y", "on"}:
        return True
    if vl in {"0", "false", "no", "n", "off"}:
        return False
    if _is_prod():
        raise StatusEndpointConfigError(f"invalid_boolean_env:{name}")
    return bool(default)


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return int(default)
        if isinstance(v, bool):
            return int(default)
        return int(v)
    except Exception:
        return int(default)


def _safe_executor(request: Request):
    try:
        return _executor(request)
    except Exception:
        return None


def _safe_snapshot(request: Request) -> Json:
    try:
        st = _snapshot(request)
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def _safe_mempool_size(request: Request) -> int:
    try:
        mp = _mempool(request)
        return int(getattr(mp, "size", lambda: 0)())
    except Exception:
        return 0


def _safe_att_pool_size(request: Request) -> int:
    try:
        ap = _att_pool(request)
        return int(getattr(ap, "size", lambda: 0)())
    except Exception:
        return 0


def _safe_tx_index_hash(ex: Any) -> str:
    if ex is None:
        return ""
    fn = getattr(ex, "tx_index_hash", None)
    if callable(fn):
        try:
            return str(fn() or "").strip()
        except Exception:
            return ""
    v = getattr(ex, "tx_index_hash", None)
    return str(v or "").strip() if isinstance(v, str) else ""


def _safe_schema_version(st: Json, ex: Any) -> str:
    meta = st.get("meta") if isinstance(st.get("meta"), dict) else {}
    sv = str(meta.get("schema_version") or "").strip()
    if sv:
        return sv
    if ex is not None:
        v = getattr(ex, "_schema_version_cached", None)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "1"


def _startup_fingerprint(st: Json, ex: Any) -> Json:
    chain_id = str(st.get("chain_id") or _env_str("WEALL_CHAIN_ID", "weall-dev"))
    node_id = str(getattr(ex, "node_id", "") or _env_str("WEALL_NODE_ID", "local-node"))
    tx_index_hash = _safe_tx_index_hash(ex)
    schema_version = _safe_schema_version(st, ex)
    validator_epoch = 0
    validator_set_hash = ""
    bft_enabled = _env_bool("WEALL_BFT_ENABLED", False)
    if ex is not None:
        try:
            validator_epoch = int(getattr(ex, "_current_validator_epoch", lambda: 0)() or 0)
        except Exception:
            validator_epoch = 0
        try:
            validator_set_hash = str(getattr(ex, "_current_validator_set_hash", lambda: "")() or "")
        except Exception:
            validator_set_hash = ""
        try:
            bft_enabled = bool(getattr(ex, "_bft_enabled", bft_enabled))
        except Exception:
            pass
    return runtime_startup_fingerprint(
        chain_id=chain_id,
        node_id=node_id,
        tx_index_hash=tx_index_hash,
        schema_version=schema_version,
        bft_enabled=bool(bft_enabled),
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash,
    )




def _bootstrap_status() -> Json:
    try:
        cfg = load_chain_config()
        return production_bootstrap_report(cfg)
    except Exception as exc:
        return {
            "ok": False,
            "issues": [f"failed to load chain config: {exc}"],
            "observer_first_recommended": True,
            "recommended_join_mode": "observer_first_then_verify_then_enable_bft_signing",
        }

def _safe_block_loop(ex: Any) -> Json:
    if ex is None:
        return {"running": None, "unhealthy": None, "last_error": None, "consecutive_failures": None}

    def _get(name: str) -> Any:
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
        "last_error": str(last_error or "") if last_error is not None else None,
        "consecutive_failures": _safe_int(consecutive, 0) if consecutive is not None else None,
    }


def _safe_peer_debug(request: Request) -> Json:
    net = getattr(request.app.state, "net_node", None)
    if net is None:
        net = getattr(request.app.state, "net", None)
    if net is None:
        return {
            "enabled": False,
            "counts": {
                "peers_total": 0,
                "peers_established": 0,
                "peers_identity_verified": 0,
                "peers_banned": 0,
            },
            "peers": [],
        }
    try:
        dbg = net.peers_debug()
        if isinstance(dbg, dict):
            return dbg
    except Exception:
        pass
    return {
        "enabled": True,
        "counts": {
            "peers_total": None,
            "peers_established": None,
            "peers_identity_verified": None,
            "peers_banned": None,
        },
        "peers": [],
    }


def _safe_bft_forensics(ex: Any) -> Json:
    if ex is None:
        return {
            "ok": False,
            "chain_id": "",
            "node_id": "",
            "diagnostics": _safe_bft_diag(ex),
            "recent_rejection_summary": {"count": 0, "by_reason": {}, "by_message_type": {}, "latest": None},
            "recent_rejections": [],
            "recent_key_events": [],
            "pending_fetch_request_descriptors": [],
            "pending_outbound_messages": [],
            "journal_tail": [],
        }
    fn = getattr(ex, "bft_operator_forensics", None)
    if callable(fn):
        try:
            out = fn()
            if isinstance(out, dict):
                return out
        except Exception:
            pass
    return {
        "ok": True,
        "chain_id": str(getattr(ex, "chain_id", "") or ""),
        "node_id": str(getattr(ex, "node_id", "") or ""),
        "diagnostics": _safe_bft_diag(ex),
        "recent_rejection_summary": {"count": 0, "by_reason": {}, "by_message_type": {}, "latest": None},
        "recent_rejections": [],
        "recent_key_events": [],
        "pending_fetch_request_descriptors": [],
        "pending_outbound_messages": [],
        "journal_tail": [],
    }


def _safe_bft_diag(ex: Any) -> Json:
    if ex is None:
        return {
            "view": 0,
            "high_qc_id": "",
            "locked_qc_id": "",
            "finalized_block_id": "",
            "pending_remote_blocks": [],
            "pending_remote_blocks_count": 0,
            "pending_candidates": [],
            "pending_candidates_count": 0,
            "pending_missing_qcs": [],
            "pending_missing_qcs_count": 0,
            "pending_fetch_requests": [],
            "pending_fetch_requests_count": 0,
            "pending_artifacts_pruned": False,
            "pacemaker_timeout_ms": 0,
            "stalled": False,
            "stall_reason": "unknown",
            "tip_ts_ms": 0,
            "clock_skew_ahead_ms": 0,
            "clock_skew_warning": False,
            "protocol_profile_hash": "",
            "schema_version": "",
            "tx_index_hash": "",
            "reputation_scale": 0,
            "max_block_future_drift_ms": 0,
            "clock_skew_warn_ms": 0,
            "journal_tail": [],
        }
    fn = getattr(ex, "bft_diagnostics", None)
    if callable(fn):
        try:
            out = fn()
            if isinstance(out, dict):
                return out
        except Exception:
            pass
    return {
        "view": 0,
        "high_qc_id": "",
        "locked_qc_id": "",
        "finalized_block_id": "",
        "pending_remote_blocks": [],
        "pending_remote_blocks_count": 0,
        "pending_candidates": [],
        "pending_candidates_count": 0,
        "pending_missing_qcs": [],
        "pending_missing_qcs_count": 0,
        "pending_fetch_requests": [],
        "pending_fetch_requests_count": 0,
        "pacemaker_timeout_ms": 0,
        "stalled": False,
        "stall_reason": "unknown",
        "tip_ts_ms": 0,
        "clock_skew_ahead_ms": 0,
        "clock_skew_warning": False,
        "protocol_profile_hash": "",
        "schema_version": "",
        "tx_index_hash": _safe_tx_index_hash(ex),
        "reputation_scale": 0,
        "max_block_future_drift_ms": 0,
        "clock_skew_warn_ms": 0,
        "journal_tail": [],
    }


def _safe_qc(qc: Any) -> Optional[Json]:
    if not isinstance(qc, dict):
        return None
    votes = qc.get("votes") if isinstance(qc.get("votes"), (list, tuple)) else []
    return {
        "block_id": str(qc.get("block_id") or "").strip(),
        "parent_id": str(qc.get("parent_id") or "").strip(),
        "view": _safe_int(qc.get("view"), 0),
        "vote_count": int(len(votes)),
    }


def _consensus_contract(validators: List[str]) -> Json:
    summary = consensus_contract_summary(validators)
    count = _safe_int(summary.get("normalized_validator_count"), 0)
    return {
        **summary,
        "quorum_threshold": quorum_threshold(count) if count > 0 else 0,
        "notes": [
            "Leader selection is deterministic round-robin over the sorted active validator set.",
            "QC formation and timeout progress both use ceil(2n/3).",
            "Finalization follows the HotStuff 3-chain rule.",
        ],
    }


@router.get("/status")
def status(request: Request) -> Json:
    ex = _safe_executor(request)
    st = _safe_snapshot(request)

    ledger = LedgerView.from_ledger(st if isinstance(st, dict) else {})

    height = int(st.get("height") or 0)
    tip = str(st.get("tip") or "")
    chain_id = str(st.get("chain_id") or _env_str("WEALL_CHAIN_ID", "weall-dev"))
    node_id = str(getattr(ex, "node_id", "") or _env_str("WEALL_NODE_ID", "local-node"))

    mempool_size = _safe_mempool_size(request)
    att_pool_size = _safe_att_pool_size(request)

    active_validators: List[str] = ledger.get_active_validator_set() or []
    active_validator_count = int(len(active_validators))
    finalized = st.get("finalized") if isinstance(st.get("finalized"), dict) else {}

    return {
        "ok": True,
        "chain_id": chain_id,
        "node_id": node_id,
        "height": height,
        "tip": tip,
        "tip_hash": str(st.get("tip_hash") or ""),
        "tip_ts_ms": _safe_int(st.get("tip_ts_ms") or st.get("last_block_ts_ms"), 0),
        "finalized_height": _safe_int(finalized.get("height") if isinstance(finalized, dict) else 0, 0),
        "finalized_block_id": str(finalized.get("block_id") if isinstance(finalized, dict) else ""),
        "mempool_size": mempool_size,
        "attestation_pool_size": att_pool_size,
        "active_validator_count": active_validator_count,
        "mode": _env_str("WEALL_MODE", "prod"),
        "db_path": _env_str("WEALL_DB_PATH", "./data/weall.db"),
        "tx_index_hash": _safe_tx_index_hash(ex),
        "consensus_contract": _consensus_contract(active_validators),
        "startup_fingerprint": _startup_fingerprint(st, ex),
        "bootstrap": _bootstrap_status(),
    }


@router.get("/chain/head")
def chain_head(request: Request) -> Json:
    st = _safe_snapshot(request)

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
    limit = _env_int("WEALL_STATUS_MEMPOOL_LIMIT", 50)
    limit = max(1, min(int(limit), 500))

    try:
        mp = _mempool(request)
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
    st = _safe_snapshot(request)
    tip = str(st.get("tip") or "")

    if not tip:
        return {"ok": True, "block_id": "", "count": 0, "items": []}

    limit = _env_int("WEALL_STATUS_ATTESTATIONS_LIMIT", 50)
    limit = max(1, min(int(limit), 500))

    try:
        ap = _att_pool(request)
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


@router.get("/status/consensus")
def status_consensus(request: Request) -> Json:
    ex = _safe_executor(request)
    st = _safe_snapshot(request)
    ledger = LedgerView.from_ledger(st if isinstance(st, dict) else {})

    chain_id = str(st.get("chain_id") or _env_str("WEALL_CHAIN_ID", "weall-dev"))
    node_id = str(getattr(ex, "node_id", "") or _env_str("WEALL_NODE_ID", "local-node"))
    validator_account = _env_str("WEALL_VALIDATOR_ACCOUNT", "")
    active_validators = ledger.get_active_validator_set() or []
    active_count = int(len(active_validators))
    normalized_validators = consensus_contract_summary(active_validators).get("normalized_validator_set") or []

    bft = st.get("bft") if isinstance(st.get("bft"), dict) else {}
    diag = _safe_bft_diag(ex)
    view = _safe_int(diag.get("view"), 0)
    if view <= 0:
        view = _safe_int(bft.get("view"), 0)
    current_leader = leader_for_view(active_validators, view) if active_validators else ""
    next_leader = leader_for_view(active_validators, view + 1) if active_validators else ""
    q_threshold = quorum_threshold(active_count) if active_count > 0 else 0
    peer_dbg = _safe_peer_debug(request)
    consensus_root = st.get("consensus") if isinstance(st.get("consensus"), dict) else {}
    phase_root = consensus_root.get("phase") if isinstance(consensus_root.get("phase"), dict) else {}
    consensus_phase = normalize_consensus_phase(phase_root.get("current"), validator_count=active_count)
    security_summary = consensus_security_summary(active_validators, phase=consensus_phase)

    return {
        "ok": True,
        "chain_id": chain_id,
        "node_id": node_id,
        "mode": _env_str("WEALL_MODE", "prod"),
        "bft_enabled": _env_bool("WEALL_BFT_ENABLED", False),
        "validator_account": validator_account,
        "height": _safe_int(st.get("height"), 0),
        "tip": str(st.get("tip") or ""),
        "tip_hash": str(st.get("tip_hash") or ""),
        "tip_ts_ms": _safe_int(st.get("tip_ts_ms") or st.get("last_block_ts_ms"), 0),
        "finalized_height": _safe_int((st.get("finalized") or {}).get("height") if isinstance(st.get("finalized"), dict) else 0, 0),
        "finalized_block_id": str((st.get("finalized") or {}).get("block_id") if isinstance(st.get("finalized"), dict) else ""),
        "view": view,
        "active_validators": list(active_validators),
        "normalized_active_validators": list(normalized_validators),
        "active_validator_count": active_count,
        "quorum_threshold": q_threshold,
        "consensus_phase": consensus_phase,
        "consensus_phase_pending": phase_root.get("pending") if isinstance(phase_root.get("pending"), dict) else None,
        "security_summary": security_summary,
        "current_leader": current_leader,
        "local_is_active_validator": bool(validator_account and validator_account in active_validators),
        "local_is_expected_leader": bool(validator_account and validator_account == current_leader),
        "next_leader": next_leader,
        "high_qc": _safe_qc(bft.get("high_qc"))
        or (
            {"block_id": str(diag.get("high_qc_id") or ""), "parent_id": "", "view": 0, "vote_count": 0}
            if str(diag.get("high_qc_id") or "").strip()
            else None
        ),
        "locked_qc": _safe_qc(bft.get("locked_qc"))
        or (
            {"block_id": str(diag.get("locked_qc_id") or ""), "parent_id": "", "view": 0, "vote_count": 0}
            if str(diag.get("locked_qc_id") or "").strip()
            else None
        ),
        "peer_counts": peer_dbg.get("counts") if isinstance(peer_dbg.get("counts"), dict) else {},
        "block_loop": _safe_block_loop(ex),
        "tx_index_hash": _safe_tx_index_hash(ex),
        "consensus_contract": _consensus_contract(active_validators),
        "startup_fingerprint": _startup_fingerprint(st, ex),
        "diagnostics": {
            "stalled": bool(diag.get("stalled", False)),
            "stall_reason": str(diag.get("stall_reason") or "unknown"),
            "stalled_since_ts_ms": _safe_int(diag.get("stalled_since_ts_ms"), 0),
            "stalled_for_ms": _safe_int(diag.get("stalled_for_ms"), 0),
            "last_progress_ts_ms": _safe_int(diag.get("last_progress_ts_ms"), 0),
            "last_view_advanced_ts_ms": _safe_int(diag.get("last_view_advanced_ts_ms"), 0),
            "last_qc_observed_ts_ms": _safe_int(diag.get("last_qc_observed_ts_ms"), 0),
            "last_timeout_emitted_ts_ms": _safe_int(diag.get("last_timeout_emitted_ts_ms"), 0),
            "last_fetch_requested_ts_ms": _safe_int(diag.get("last_fetch_requested_ts_ms"), 0),
            "last_fetch_satisfied_ts_ms": _safe_int(diag.get("last_fetch_satisfied_ts_ms"), 0),
            "pending_remote_blocks_count": _safe_int(diag.get("pending_remote_blocks_count"), 0),
            "pending_candidates_count": _safe_int(diag.get("pending_candidates_count"), 0),
            "pending_missing_qcs_count": _safe_int(diag.get("pending_missing_qcs_count"), 0),
            "pending_fetch_requests_count": _safe_int(diag.get("pending_fetch_requests_count"), 0),
            "pending_artifacts_pruned": bool(diag.get("pending_artifacts_pruned", False)),
            "clock_skew_ahead_ms": _safe_int(diag.get("clock_skew_ahead_ms"), 0),
            "clock_skew_warning": bool(diag.get("clock_skew_warning", False)),
            "median_time_past_ms": _safe_int(diag.get("median_time_past_ms"), 0),
            "chain_time_floor_ms": _safe_int(diag.get("chain_time_floor_ms"), 0),
            "timestamp_rule": str(diag.get("timestamp_rule") or "chain_time_floor_only"),
            "uses_wall_clock_future_guard": bool(diag.get("uses_wall_clock_future_guard", False)),
            "pacemaker_timeout_ms": _safe_int(diag.get("pacemaker_timeout_ms"), 0),
            "recent_rejection_summary": diag.get("recent_rejection_summary") if isinstance(diag.get("recent_rejection_summary"), dict) else {"count": 0, "by_reason": {}, "by_message_type": {}, "latest": None},
        },
        "runtime_profile": {
            "protocol_profile_hash": str(diag.get("protocol_profile_hash") or runtime_protocol_profile_hash()),
            "reputation_scale": _safe_int(diag.get("reputation_scale"), 0),
            "max_block_future_drift_ms": _safe_int(
                diag.get("max_block_future_drift_ms"), runtime_max_block_future_drift_ms()
            ),
            "max_block_time_advance_ms": _safe_int(diag.get("max_block_time_advance_ms"), 0),
            "clock_skew_warn_ms": _safe_int(diag.get("clock_skew_warn_ms"), runtime_clock_skew_warn_ms()),
            "timestamp_rule": str(diag.get("timestamp_rule") or "chain_time_floor_only"),
        },
    }


@router.get("/status/consensus/forensics")
def status_consensus_forensics(request: Request) -> Json:
    ex = _safe_executor(request)
    st = _safe_snapshot(request)
    out = _safe_bft_forensics(ex)
    if not isinstance(out, dict):
        out = {}
    out.setdefault("ok", True)
    out.setdefault("chain_id", str(st.get("chain_id") or _env_str("WEALL_CHAIN_ID", "weall-dev")))
    out.setdefault("node_id", str(getattr(ex, "node_id", "") or _env_str("WEALL_NODE_ID", "local-node")))
    return out


@router.get("/status/operator")
def status_operator(request: Request) -> Json:
    ex = _safe_executor(request)
    st = _safe_snapshot(request)
    peer_dbg = _safe_peer_debug(request)

    diag = _safe_bft_diag(ex)
    ledger = LedgerView.from_ledger(st if isinstance(st, dict) else {})
    active_validators = ledger.get_active_validator_set() or []
    posture = effective_runtime_consensus_posture()

    return {
        "ok": True,
        "mode": _env_str("WEALL_MODE", "prod"),
        "chain_id": str(st.get("chain_id") or _env_str("WEALL_CHAIN_ID", "weall-dev")),
        "node_id": str(getattr(ex, "node_id", "") or _env_str("WEALL_NODE_ID", "local-node")),
        "db_path": _env_str("WEALL_DB_PATH", "./data/weall.db"),
        "tx_index_hash": _safe_tx_index_hash(ex),
        "height": _safe_int(st.get("height"), 0),
        "tip": str(st.get("tip") or ""),
        "mempool_size": _safe_mempool_size(request),
        "attestation_pool_size": _safe_att_pool_size(request),
        "metrics_enabled": bool(metrics_enabled()),
        "public_debug_enabled": _env_bool("WEALL_ENABLE_PUBLIC_DEBUG", False),
        "block_loop": _safe_block_loop(ex),
        "net": {
            "enabled": _env_bool("WEALL_NET_ENABLED", True),
            "peer_identity_required": _env_bool("WEALL_NET_REQUIRE_IDENTITY", False),
            "peer_counts": peer_dbg.get("counts") if isinstance(peer_dbg.get("counts"), dict) else {},
            "peers": peer_dbg.get("peers") if isinstance(peer_dbg.get("peers"), list) else [],
        },
        "consensus": {
            "bft_enabled": _env_bool("WEALL_BFT_ENABLED", False),
            "validator_account": _env_str("WEALL_VALIDATOR_ACCOUNT", ""),
            "effective_posture": posture,
            "qc_less_blocks_allowed": bool(posture.get("qc_less_blocks_allowed", False)),
            "unsafe_autocommit": bool(posture.get("unsafe_autocommit_allowed", False)),
            "sigverify_required": bool(posture.get("sigverify_required", True)),
            "trusted_anchor_required": bool(posture.get("trusted_anchor_required", True)),
            "profile_enforced": bool(posture.get("profile_enforced", False)),
            "stalled": bool(diag.get("stalled", False)),
            "stall_reason": str(diag.get("stall_reason") or "unknown"),
            "stalled_since_ts_ms": _safe_int(diag.get("stalled_since_ts_ms"), 0),
            "stalled_for_ms": _safe_int(diag.get("stalled_for_ms"), 0),
            "last_progress_ts_ms": _safe_int(diag.get("last_progress_ts_ms"), 0),
            "last_view_advanced_ts_ms": _safe_int(diag.get("last_view_advanced_ts_ms"), 0),
            "last_qc_observed_ts_ms": _safe_int(diag.get("last_qc_observed_ts_ms"), 0),
            "last_timeout_emitted_ts_ms": _safe_int(diag.get("last_timeout_emitted_ts_ms"), 0),
            "pending_remote_blocks_count": _safe_int(diag.get("pending_remote_blocks_count"), 0),
            "pending_candidates_count": _safe_int(diag.get("pending_candidates_count"), 0),
            "pending_missing_qcs_count": _safe_int(diag.get("pending_missing_qcs_count"), 0),
            "pending_fetch_requests_count": _safe_int(diag.get("pending_fetch_requests_count"), 0),
            "pending_artifacts_pruned": bool(diag.get("pending_artifacts_pruned", False)),
            "pacemaker_timeout_ms": _safe_int(diag.get("pacemaker_timeout_ms"), 0),
            "clock_skew_warning": bool(diag.get("clock_skew_warning", False)),
            "median_time_past_ms": _safe_int(diag.get("median_time_past_ms"), 0),
            "chain_time_floor_ms": _safe_int(diag.get("chain_time_floor_ms"), 0),
            "timestamp_rule": str(diag.get("timestamp_rule") or "chain_time_floor_only"),
            "uses_wall_clock_future_guard": bool(diag.get("uses_wall_clock_future_guard", False)),
            "recent_rejection_summary": diag.get("recent_rejection_summary") if isinstance(diag.get("recent_rejection_summary"), dict) else {"count": 0, "by_reason": {}, "by_message_type": {}, "latest": None},
            "contract": _consensus_contract(active_validators),
        },
        "runtime_profile": {
            "protocol_profile_hash": str(diag.get("protocol_profile_hash") or runtime_protocol_profile_hash()),
            "reputation_scale": _safe_int(diag.get("reputation_scale"), 0),
            "max_block_future_drift_ms": _safe_int(
                diag.get("max_block_future_drift_ms"), runtime_max_block_future_drift_ms()
            ),
            "max_block_time_advance_ms": _safe_int(diag.get("max_block_time_advance_ms"), 0),
            "clock_skew_warn_ms": _safe_int(diag.get("clock_skew_warn_ms"), runtime_clock_skew_warn_ms()),
            "timestamp_rule": str(diag.get("timestamp_rule") or "chain_time_floor_only"),
        },
        "startup_fingerprint": _startup_fingerprint(st, ex),
        "bootstrap": _bootstrap_status(),
    }
