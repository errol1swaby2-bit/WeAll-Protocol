from __future__ import annotations

from pathlib import Path

from weall.api.mode_isolation import (
    controlled_devnet_bootstrap_secret_route_allowed,
    demo_mode_isolation_issue,
)


def _safe_local_rehearsal_env(tmp_path: Path) -> dict[str, str]:
    devnet_dir = tmp_path / ".weall-devnet"
    secret_path = devnet_dir / "generated" / "dev-bootstrap-genesis-secret.json"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_text("{}", encoding="utf-8")
    return {
        "WEALL_MODE": "devnet",
        "WEALL_RUNTIME_PROFILE": "controlled_devnet",
        "WEALL_DEVNET_DIR": str(devnet_dir),
        "WEALL_ENABLE_DEMO_SEED_ROUTE": "0",
        "WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE": "1",
        "WEALL_DEV_BOOTSTRAP_SECRET_PATH": str(secret_path),
        "WEALL_POH_BOOTSTRAP_OPEN": "0",
        "WEALL_SIGVERIFY": "1",
        "WEALL_STRICT_TX_SIG_DOMAIN": "1",
        "WEALL_ENABLE_OPERATOR_POH": "0",
        "WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE": "0",
        "WEALL_ALLOW_DIRECT_SESSION_MUTATION": "0",
        "GUNICORN_BIND": "127.0.0.1:8001",
    }


def test_local_controlled_rehearsal_can_boot_with_loopback_secret_route(tmp_path: Path) -> None:
    env = _safe_local_rehearsal_env(tmp_path)

    assert controlled_devnet_bootstrap_secret_route_allowed(env) is True
    assert demo_mode_isolation_issue(env) is None


def test_controlled_rehearsal_secret_route_rejects_non_loopback_bind(tmp_path: Path) -> None:
    env = _safe_local_rehearsal_env(tmp_path)
    env["GUNICORN_BIND"] = "0.0.0.0:8001"

    assert controlled_devnet_bootstrap_secret_route_allowed(env) is False
    assert demo_mode_isolation_issue(env) == "dev_bootstrap_secret_route_forbidden_in_devnet_or_prod"


def test_controlled_rehearsal_secret_route_rejects_secret_outside_devnet_generated(tmp_path: Path) -> None:
    env = _safe_local_rehearsal_env(tmp_path)
    bad_secret = tmp_path / "outside-secret.json"
    bad_secret.write_text("{}", encoding="utf-8")
    env["WEALL_DEV_BOOTSTRAP_SECRET_PATH"] = str(bad_secret)

    assert controlled_devnet_bootstrap_secret_route_allowed(env) is False
    assert demo_mode_isolation_issue(env) == "dev_bootstrap_secret_route_forbidden_in_devnet_or_prod"


def test_controlled_rehearsal_secret_route_still_rejects_demo_seed_and_session_mutation(tmp_path: Path) -> None:
    env = _safe_local_rehearsal_env(tmp_path)
    env["WEALL_ENABLE_DEMO_SEED_ROUTE"] = "1"
    assert controlled_devnet_bootstrap_secret_route_allowed(env) is False
    assert demo_mode_isolation_issue(env) == "demo_seed_route_forbidden_in_devnet_or_prod"

    env = _safe_local_rehearsal_env(tmp_path)
    env["WEALL_ALLOW_DIRECT_SESSION_MUTATION"] = "1"
    assert controlled_devnet_bootstrap_secret_route_allowed(env) is False
    assert demo_mode_isolation_issue(env) == "dev_bootstrap_secret_route_forbidden_in_devnet_or_prod"
