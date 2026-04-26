from __future__ import annotations

import os
from collections.abc import Mapping

Env = Mapping[str, str | None]


def _truthy(value: str | None) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    return raw in {"1", "true", "yes", "y", "on"}


def runtime_profile_name(environ: Env | None = None) -> str:
    env = environ or os.environ
    return (
        env.get("WEALL_RUNTIME_PROFILE")
        or env.get("WEALL_PROTOCOL_PROFILE")
        or env.get("WEALL_PROFILE")
        or ""
    ).strip().lower()


def runtime_mode_name(environ: Env | None = None) -> str:
    env = environ or os.environ
    return str(env.get("WEALL_MODE", "") or "").strip().lower()


def demo_mode_isolation_issue(environ: Env | None = None) -> str | None:
    """Return a fail-closed startup issue when demo authority leaks modes.

    Seeded-demo endpoints directly mutate canonical demo state and may expose a
    local bootstrap secret. They are acceptable only in explicit single-node
    seeded-demo mode. Multi-node devnet and production-like modes must not start
    when those knobs are present, even if the individual route handler would hide
    itself at request time.
    """

    env = environ or os.environ
    profile = runtime_profile_name(env)
    mode = runtime_mode_name(env)
    demo_env_enabled = _truthy(env.get("WEALL_ENABLE_DEMO_SEED_ROUTE"))
    secret_env_enabled = _truthy(env.get("WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE"))
    dangerous_mode = mode in {"prod", "production", "production_like", "devnet", "multi_node_devnet"}

    if dangerous_mode and profile == "seeded_demo":
        return "seeded_demo_profile_forbidden_in_devnet_or_prod"
    if dangerous_mode and demo_env_enabled:
        return "demo_seed_route_forbidden_in_devnet_or_prod"
    if dangerous_mode and secret_env_enabled:
        return "dev_bootstrap_secret_route_forbidden_in_devnet_or_prod"
    return None
