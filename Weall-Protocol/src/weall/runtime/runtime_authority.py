from __future__ import annotations

from typing import Any, Mapping

from weall.runtime.node_runtime_config import (
    PRODUCTION_SERVICE,
    NodeRuntimeConfig,
    resolve_node_runtime_config_from_env,
)


def strict_lifecycle_authority_mode() -> bool:
    cfg = resolve_node_runtime_config_from_env()
    return bool(cfg.requested_state == PRODUCTION_SERVICE)


def runtime_mode_is_prod() -> bool:
    try:
        mode = str(__import__("os").environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"
    except Exception:
        mode = "prod"
    return bool(mode == "prod")


def strict_runtime_authority_mode() -> bool:
    return bool(runtime_mode_is_prod() or strict_lifecycle_authority_mode())


def authority_contract_from_lifecycle(
    lifecycle: Mapping[str, Any] | None,
    runtime_cfg: NodeRuntimeConfig | None = None,
    *,
    source: str = "runtime",
) -> dict[str, Any]:
    cfg = runtime_cfg if runtime_cfg is not None else resolve_node_runtime_config_from_env()
    lifecycle = lifecycle if isinstance(lifecycle, Mapping) else {}

    requested_roles = list(cfg.requested_roles)
    effective_roles_raw = lifecycle.get("service_roles_effective")
    effective_roles = [str(x) for x in effective_roles_raw] if isinstance(effective_roles_raw, (list, tuple)) else []
    reasons_raw = lifecycle.get("promotion_failure_reasons")
    reasons = [str(x) for x in reasons_raw] if isinstance(reasons_raw, (list, tuple)) else []

    helper_requested = bool(lifecycle.get("helper_enabled_requested", cfg.helper_enabled_requested))
    helper_effective = bool(lifecycle.get("helper_enabled_effective", False))
    bft_requested = bool(lifecycle.get("bft_enabled_requested", cfg.bft_enabled_requested))
    bft_effective = bool(lifecycle.get("bft_enabled_effective", False))

    return {
        "contract_source": str(source or "runtime"),
        "strict_runtime_authority_mode": bool(strict_runtime_authority_mode()),
        "requested_state": str(lifecycle.get("requested_state", cfg.requested_state) or cfg.requested_state),
        "effective_state": str(lifecycle.get("effective_state", "") or ""),
        "requested_roles": requested_roles,
        "effective_roles": effective_roles,
        "validator_requested": bool("validator" in requested_roles or bft_requested),
        "validator_effective": bool("validator" in effective_roles or bft_effective),
        "helper_requested": helper_requested,
        "helper_effective": helper_effective,
        "bft_requested": bft_requested,
        "bft_effective": bft_effective,
        "startup_action": str(lifecycle.get("startup_action", "") or ""),
        "promotion_failure_reasons": reasons,
    }


def startup_authority_contract_from_app_state(app_state: Any) -> dict[str, Any]:
    try:
        contract = getattr(app_state, "startup_authority_contract", None)
    except Exception:
        contract = None
    return contract if isinstance(contract, dict) else {}


def effective_bft_enabled(*, executor: Any | None = None, default: bool = False) -> bool:
    if executor is not None:
        try:
            return bool(getattr(executor, '_bft_enabled_effective'))
        except Exception:
            pass
        try:
            status_fn = getattr(executor, 'node_lifecycle_status', None)
            if callable(status_fn):
                status = status_fn()
                if isinstance(status, dict):
                    if strict_runtime_authority_mode():
                        return bool(status.get('bft_enabled_effective', False))
                    requested = bool(status.get('bft_enabled_requested', default))
                    return bool(status.get('bft_enabled_effective', requested) or requested)
        except Exception:
            pass
    cfg = resolve_node_runtime_config_from_env()
    if strict_runtime_authority_mode():
        return False
    return bool(cfg.bft_enabled_requested or default)
