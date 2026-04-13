from __future__ import annotations

import os
from dataclasses import dataclass

BOOTSTRAP_REGISTRATION = "bootstrap_registration"
PRODUCTION_SERVICE = "production_service"
MAINTENANCE_RESTRICTED = "maintenance_restricted"
REFUSED_STARTUP = "refused_startup"

_ALLOWED_STATES = {
    BOOTSTRAP_REGISTRATION,
    PRODUCTION_SERVICE,
    MAINTENANCE_RESTRICTED,
    REFUSED_STARTUP,
}

_ALLOWED_SERVICE_ROLES = {
    "validator",
    "helper",
    "node_operator",
    "storage_operator",
    "general_service",
}

_ALLOWED_PEER_PROFILE_ENFORCEMENT = {"strict", "advisory"}

_ALLOWED_TRUE = {"1", "true", "yes", "y", "on"}
_ALLOWED_FALSE = {"0", "false", "no", "n", "off"}


@dataclass(frozen=True, slots=True)
class NodeRuntimeConfig:
    requested_state: str
    raw_state: str
    requested_roles: tuple[str, ...]
    invalid_roles: tuple[str, ...]
    helper_enabled_requested: bool
    bft_enabled_requested: bool
    peer_profile_enforcement: str
    env_vars_applied: tuple[str, ...]

    def config_source_summary(self) -> dict[str, object]:
        return {
            "env_applied": bool(self.env_vars_applied),
            "env_vars_applied": list(self.env_vars_applied),
            "cli_applied": False,
            "file_applied": False,
        }


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    if s in _ALLOWED_TRUE:
        return True
    if s in _ALLOWED_FALSE:
        return False
    return bool(default)


def _csv_env(name: str) -> tuple[str, ...]:
    raw = str(os.environ.get(name) or "").strip()
    if not raw:
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        item = str(part).strip().lower()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return tuple(out)


def _requested_state_from_env() -> tuple[str, str]:
    raw = str(os.environ.get("WEALL_NODE_LIFECYCLE_STATE") or "").strip().lower()
    if raw in _ALLOWED_STATES:
        return raw, raw
    if raw:
        return REFUSED_STARTUP, raw
    return BOOTSTRAP_REGISTRATION, ""


def _peer_profile_enforcement_from_env() -> str:
    raw = str(os.environ.get("WEALL_PEER_PROFILE_ENFORCEMENT") or "").strip().lower()
    if raw in _ALLOWED_PEER_PROFILE_ENFORCEMENT:
        return raw
    return "strict"


def resolve_node_runtime_config_from_env() -> NodeRuntimeConfig:
    requested_state, raw_state = _requested_state_from_env()
    requested_roles = _csv_env("WEALL_SERVICE_ROLES")
    invalid_roles = tuple(sorted({r for r in requested_roles if r not in _ALLOWED_SERVICE_ROLES}))
    helper_enabled_requested = _env_bool("WEALL_HELPER_MODE_ENABLED", False)
    bft_enabled_requested = _env_bool("WEALL_BFT_ENABLED", False)
    peer_profile_enforcement = _peer_profile_enforcement_from_env()

    tracked_vars = (
        "WEALL_NODE_LIFECYCLE_STATE",
        "WEALL_SERVICE_ROLES",
        "WEALL_HELPER_MODE_ENABLED",
        "WEALL_BFT_ENABLED",
        "WEALL_PEER_PROFILE_ENFORCEMENT",
    )
    env_vars_applied = tuple(name for name in tracked_vars if os.environ.get(name) is not None)

    return NodeRuntimeConfig(
        requested_state=requested_state,
        raw_state=raw_state,
        requested_roles=requested_roles,
        invalid_roles=invalid_roles,
        helper_enabled_requested=helper_enabled_requested,
        bft_enabled_requested=bft_enabled_requested,
        peer_profile_enforcement=peer_profile_enforcement,
        env_vars_applied=env_vars_applied,
    )
