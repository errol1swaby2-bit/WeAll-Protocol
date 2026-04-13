from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Request

from weall.runtime.helper_operator_diagnostics import build_helper_operator_diagnostic
from weall.runtime.helper_preflight_gate import (
    ProductionPreflightInput,
    decide_production_preflight,
)
from weall.runtime.helper_readiness_report import build_helper_readiness_report
from weall.runtime.helper_startup_integration import (
    HelperStartupConfig,
    evaluate_helper_startup,
)
from weall.runtime.node_runtime_config import resolve_node_runtime_config_from_env
from weall.runtime.runtime_authority import (
    authority_contract_from_lifecycle,
    startup_authority_contract_from_app_state,
)

router = APIRouter()

_ALLOWED_TRUE = {"1", "true", "yes", "y", "on"}
_ALLOWED_FALSE = {"0", "false", "no", "n", "off"}


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
    return bool(default)


def _safe_str(v: Any, default: str = "") -> str:
    try:
        if v is None:
            return str(default)
        return str(v)
    except Exception:
        return str(default)


def _helper_release_gate_report(app_state: Any):
    try:
        return getattr(app_state, "helper_release_gate_report", None)
    except Exception:
        return None


def _chain_id(request: Request) -> str:
    ex = getattr(request.app.state, "executor", None)
    if ex is not None:
        snap = getattr(ex, "snapshot", None)
        if callable(snap):
            try:
                out = snap()
                if isinstance(out, dict):
                    cid = _safe_str(out.get("chain_id"), "")
                    if cid:
                        return cid
            except Exception:
                pass
    return _safe_str(os.environ.get("WEALL_CHAIN_ID"), "")


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

@router.get("/status/helper/readiness")
def helper_readiness(request: Request) -> dict[str, Any]:
    chain_id = _chain_id(request)
    authority_contract, contract_source = _authority_contract(request)
    helper_requested = bool(authority_contract.get("helper_requested", resolve_node_runtime_config_from_env().helper_enabled_requested))
    release = _helper_release_gate_report(request.app.state)

    preflight = decide_production_preflight(
        preflight=ProductionPreflightInput(
            chain_id_ok=bool(chain_id),
            protocol_profile_ok=True,
            validator_set_ok=True,
            trusted_anchor_ok=True,
            sqlite_wal_ok=True,
            helper_release_gate=release,
            helper_mode_enabled=helper_requested,
        )
    )
    helper_authority_known = any(
        authority_contract.get(key)
        for key in ("effective_state", "startup_action", "promotion_failure_reasons", "effective_roles")
    )
    startup = evaluate_helper_startup(
        config=HelperStartupConfig(
            helper_mode_requested=helper_requested,
            helper_authority_ok=(not helper_requested) or (not helper_authority_known) or bool(authority_contract.get("helper_effective", False)),
            chain_id_ok=bool(chain_id),
            protocol_profile_ok=True,
            validator_set_ok=True,
            trusted_anchor_ok=True,
            sqlite_wal_ok=True,
        ),
        helper_release_gate=release,
    )
    diagnostic = build_helper_operator_diagnostic(status=startup)
    report = build_helper_readiness_report(
        preflight_decision=preflight,
        startup_status=startup,
        operator_diagnostic=diagnostic,
        release_gate_report=release,
    ).to_json()
    report["chain_id"] = chain_id or None
    report["helper_mode_requested"] = helper_requested
    report["helper_mode_effective"] = bool(authority_contract.get("helper_effective", False))
    report["authority_contract"] = authority_contract
    report["authority_contract_source"] = contract_source
    return report
