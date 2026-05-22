from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

Env = Mapping[str, str | None]


def _truthy(value: str | None) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    return raw in {"1", "true", "yes", "y", "on"}


def _falsy(value: str | None) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    return raw in {"0", "false", "no", "n", "off"}


_CONTROLLED_DEVNET_MODES = {"devnet", "multi_node_devnet", "controlled_devnet"}
_CONTROLLED_DEVNET_PROFILES = {"devnet", "multi_node_devnet", "controlled_devnet"}
_PRODUCTION_LIKE_MODES = {"prod", "production", "production_like"}
_DEV_SESSION_MUTATION_FLAGS = {
    "WEALL_ALLOW_DIRECT_SESSION_MUTATION",
    "WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE",
}
_OPERATOR_POH_FLAGS = {"WEALL_ENABLE_OPERATOR_POH"}

def _path_under(child: str | None, parent: str | None) -> bool:
    if not child or not parent:
        return False
    try:
        child_path = Path(child).expanduser().resolve(strict=False)
        parent_path = Path(parent).expanduser().resolve(strict=False)
    except OSError:
        return False
    try:
        child_path.relative_to(parent_path)
    except ValueError:
        return False
    return True


def _bind_is_loopback(bind: str | None) -> bool:
    raw = str(bind or "").strip()
    if not raw:
        return False
    host = raw.rsplit(":", 1)[0].strip().strip("[]")
    return host in {"127.0.0.1", "localhost", "::1"}


def controlled_devnet_bootstrap_secret_route_allowed(environ: Env | None = None) -> bool:
    """Allow the browser bootstrap-secret route only for local controlled-devnet rehearsals.

    The route exists so the one-command local two-frontend rehearsal can hydrate
    two browser sessions without direct session mutation.  It must remain
    loopback-only, path-fenced under the generated devnet directory, and absent
    from production-like modes or generic multi-machine devnet launches.
    """

    env = environ or os.environ
    if not _truthy(env.get("WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE")):
        return False

    mode = runtime_mode_name(env)
    profile = runtime_profile_name(env)
    if mode in _PRODUCTION_LIKE_MODES or profile in _PRODUCTION_LIKE_MODES:
        return False
    if profile != "controlled_devnet":
        return False
    if _truthy(env.get("WEALL_ENABLE_DEMO_SEED_ROUTE")):
        return False
    if any(_truthy(env.get(name)) for name in _DEV_SESSION_MUTATION_FLAGS):
        return False
    if any(_truthy(env.get(name)) for name in _OPERATOR_POH_FLAGS):
        return False
    if not _bind_is_loopback(env.get("GUNICORN_BIND")):
        return False

    devnet_dir = env.get("WEALL_DEVNET_DIR")
    secret_path = env.get("WEALL_DEV_BOOTSTRAP_SECRET_PATH")
    generated_dir = str(Path(str(devnet_dir or "")).expanduser() / "generated") if devnet_dir else None
    return _path_under(secret_path, generated_dir)


def dev_bootstrap_secret_route_allowed(environ: Env | None = None) -> bool:
    """Return whether the dev bootstrap secret route is safe to mount."""

    env = environ or os.environ
    if not _truthy(env.get("WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE")):
        return False
    mode = runtime_mode_name(env)
    profile = runtime_profile_name(env)
    if mode in _PRODUCTION_LIKE_MODES or profile in _PRODUCTION_LIKE_MODES:
        return False
    if profile == "seeded_demo" and mode not in {"prod", "production", "production_like", "devnet", "multi_node_devnet"}:
        return True
    return controlled_devnet_bootstrap_secret_route_allowed(env)



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


def _is_controlled_devnet(mode: str, profile: str) -> bool:
    return mode in _CONTROLLED_DEVNET_MODES or profile in _CONTROLLED_DEVNET_PROFILES


def is_controlled_devnet(environ: Env | None = None) -> bool:
    env = environ or os.environ
    return _is_controlled_devnet(runtime_mode_name(env), runtime_profile_name(env))


def is_production_like(environ: Env | None = None) -> bool:
    env = environ or os.environ
    mode = runtime_mode_name(env)
    profile = runtime_profile_name(env)
    return mode in _PRODUCTION_LIKE_MODES or profile in _PRODUCTION_LIKE_MODES


def _is_dangerous_mode(mode: str, profile: str) -> bool:
    return _is_controlled_devnet(mode, profile) or mode in _PRODUCTION_LIKE_MODES or profile in _PRODUCTION_LIKE_MODES



def direct_session_mutation_allowed(environ: Env | None = None) -> bool:
    """Direct session/device writes are a seeded-demo-only helper.

    Production, production-like, controlled devnet, and normal devnet must use
    canonical account/device/session-key transactions instead of API-local
    ledger mutation.  The direct route is retained only for explicit single-node
    seeded demo bootstraps.
    """

    env = environ or os.environ
    mode = runtime_mode_name(env)
    profile = runtime_profile_name(env)
    return (
        mode in {"dev", "local", "demo"}
        and profile == "seeded_demo"
        and _truthy(env.get("WEALL_ENABLE_DEMO_SEED_ROUTE"))
        and _truthy(env.get("WEALL_ALLOW_DIRECT_SESSION_MUTATION"))
    )

def direct_session_mutation_issue(environ: Env | None = None) -> str | None:
    """Return an issue when a request would perform non-transactional session mutation.

    The session login/create routes write session/device records directly into a
    local ledger snapshot.  That is allowed only for an explicit single-node
    seeded demo.  Production, production-like, controlled devnet, and normal
    devnet must issue session/device state through canonical transactions.
    """

    env = environ or os.environ
    if direct_session_mutation_allowed(env):
        return None
    if is_controlled_devnet(env):
        return "direct_session_mutation_forbidden_in_controlled_devnet"
    if is_production_like(env):
        return "direct_session_mutation_forbidden_in_production"
    return "direct_session_mutation_forbidden_outside_seeded_demo"


def direct_session_mutation_env_issue(environ: Env | None = None) -> str | None:
    """Return a startup issue when explicit session-helper knobs leak."""

    env = environ or os.environ
    profile = runtime_profile_name(env)
    mode = runtime_mode_name(env)
    if direct_session_mutation_allowed(env):
        return None
    for name in sorted(_DEV_SESSION_MUTATION_FLAGS):
        if _truthy(env.get(name)):
            if _is_dangerous_mode(mode, profile):
                return f"{name.lower()}_forbidden_in_devnet_or_prod"
            return f"{name.lower()}_forbidden_outside_seeded_demo"
    return None


def operator_poh_env_issue(environ: Env | None = None) -> str | None:
    """Return a startup issue when operator-driven PoH controls leak."""

    env = environ or os.environ
    if not is_controlled_devnet(env) and not is_production_like(env):
        return None
    for name in sorted(_OPERATOR_POH_FLAGS):
        if _truthy(env.get(name)):
            return "operator_poh_forbidden_in_controlled_devnet_or_prod"
    return None


def demo_mode_isolation_issue(environ: Env | None = None) -> str | None:
    """Return a fail-closed startup issue when demo or helper authority leaks modes.

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
    dangerous_mode = _is_dangerous_mode(mode, profile)
    controlled_devnet = _is_controlled_devnet(mode, profile)

    if dangerous_mode and profile == "seeded_demo":
        return "seeded_demo_profile_forbidden_in_devnet_or_prod"
    if dangerous_mode and demo_env_enabled:
        return "demo_seed_route_forbidden_in_devnet_or_prod"
    if dangerous_mode and secret_env_enabled and not dev_bootstrap_secret_route_allowed(env):
        return "dev_bootstrap_secret_route_forbidden_in_devnet_or_prod"

    # Controlled multi-node devnet must exercise the normal protocol onboarding
    # path.  Open PoH bootstrap is a local-dev/test convenience that allows a
    # subject to self-grant Live during an early height window; leaving it on in
    # devnet would contaminate Tier1 -> Tier2 -> Live readiness tests.
    if controlled_devnet and _truthy(env.get("WEALL_POH_BOOTSTRAP_OPEN")):
        return "poh_open_bootstrap_forbidden_in_controlled_devnet"

    # A devnet that accepts unsigned or weak-domain transactions is not useful
    # for external tester readiness.  Empty values are treated as unsafe here so
    # scripts must make the security posture explicit.
    if controlled_devnet and not _truthy(env.get("WEALL_SIGVERIFY")):
        return "sigverify_required_in_controlled_devnet"
    if controlled_devnet and not _truthy(env.get("WEALL_STRICT_TX_SIG_DOMAIN")):
        return "strict_tx_sig_domain_required_in_controlled_devnet"

    operator_issue = operator_poh_env_issue(env)
    if operator_issue:
        return operator_issue

    session_env_issue = direct_session_mutation_env_issue(env)
    if session_env_issue:
        return session_env_issue

    return None
