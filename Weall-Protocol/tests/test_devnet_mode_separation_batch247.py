from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.mode_isolation import demo_mode_isolation_issue, direct_session_mutation_issue

REPO_ROOT = Path(__file__).resolve().parents[1]


def _controlled_env() -> dict[str, str]:
    return {
        "WEALL_MODE": "devnet",
        "WEALL_RUNTIME_PROFILE": "controlled_devnet",
        "WEALL_ENABLE_DEMO_SEED_ROUTE": "0",
        "WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE": "0",
        "WEALL_POH_BOOTSTRAP_OPEN": "0",
        "WEALL_SIGVERIFY": "1",
        "WEALL_STRICT_TX_SIG_DOMAIN": "1",
        "WEALL_ENABLE_OPERATOR_POH": "0",
        "WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE": "0",
        "WEALL_ALLOW_DIRECT_SESSION_MUTATION": "0",
    }


def test_controlled_devnet_forbids_operator_poh_batch247() -> None:
    env = _controlled_env()
    env["WEALL_ENABLE_OPERATOR_POH"] = "1"
    assert demo_mode_isolation_issue(env) == "operator_poh_forbidden_in_controlled_devnet_or_prod"


def test_controlled_devnet_forbids_direct_session_mutation_env_batch247() -> None:
    env = _controlled_env()
    env["WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE"] = "1"
    assert (
        demo_mode_isolation_issue(env)
        == "weall_enable_dev_session_create_route_forbidden_in_devnet_or_prod"
    )

    env = _controlled_env()
    env["WEALL_ALLOW_DIRECT_SESSION_MUTATION"] = "1"
    assert (
        demo_mode_isolation_issue(env)
        == "weall_allow_direct_session_mutation_forbidden_in_devnet_or_prod"
    )


def test_controlled_devnet_session_mutation_route_fails_closed_batch247(monkeypatch) -> None:
    for k, v in _controlled_env().items():
        monkeypatch.setenv(k, v)

    assert direct_session_mutation_issue() == "direct_session_mutation_forbidden_in_controlled_devnet"

    app = create_app(boot_runtime=False)
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post("/v1/session/create", json={"account": "@demo", "session_key": "sk"})
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "direct_session_mutation_forbidden_in_controlled_devnet"

    r = client.post("/v1/session/login", json={"account": "@demo", "session_key": "sk"})
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "direct_session_mutation_forbidden_in_controlled_devnet"


def test_controlled_devnet_guard_scripts_exist_batch247() -> None:
    required = [
        "scripts/devnet_assert_no_demo_artifacts.sh",
        "scripts/devnet_assert_no_operator_poh.sh",
        "scripts/devnet_assert_no_direct_session_mutation.sh",
    ]
    for rel in required:
        path = REPO_ROOT / rel
        text = path.read_text(encoding="utf-8")
        assert path.exists()
        assert "controlled-devnet" in text

    preflight = (REPO_ROOT / "scripts/devnet_preflight_controlled_profile.sh").read_text(
        encoding="utf-8"
    )
    assert "devnet_assert_no_operator_poh.sh" in preflight
    assert "devnet_assert_no_direct_session_mutation.sh" in preflight
    assert "devnet_assert_no_demo_artifacts.sh" in preflight


def test_controlled_boot_scripts_disable_operator_and_session_helpers_batch247() -> None:
    for rel in ("scripts/devnet_boot_genesis_node.sh", "scripts/devnet_boot_joining_node.sh"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert 'export WEALL_ENABLE_OPERATOR_POH="${WEALL_ENABLE_OPERATOR_POH:-0}"' in text
        assert (
            'export WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE="${WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE:-0}"'
            in text
        )
        assert (
            'export WEALL_ALLOW_DIRECT_SESSION_MUTATION="${WEALL_ALLOW_DIRECT_SESSION_MUTATION:-0}"'
            in text
        )
