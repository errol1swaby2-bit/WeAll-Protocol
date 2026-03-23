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


@router.get("/status/helper/readiness")
def helper_readiness(request: Request) -> dict[str, Any]:
    chain_id = _chain_id(request)
    helper_requested = _env_bool("WEALL_HELPER_MODE_ENABLED", False)
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
    startup = evaluate_helper_startup(
        config=HelperStartupConfig(
            helper_mode_requested=helper_requested,
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
    return report
