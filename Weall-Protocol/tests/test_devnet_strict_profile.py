from __future__ import annotations

from pathlib import Path

from weall.api.mode_isolation import demo_mode_isolation_issue

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_controlled_devnet_requires_signature_and_strict_domain() -> None:
    env = {
        "WEALL_MODE": "devnet",
        "WEALL_RUNTIME_PROFILE": "controlled_devnet",
        "WEALL_ENABLE_DEMO_SEED_ROUTE": "0",
        "WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE": "0",
        "WEALL_POH_BOOTSTRAP_OPEN": "0",
        "WEALL_SIGVERIFY": "1",
        "WEALL_STRICT_TX_SIG_DOMAIN": "1",
    }
    assert demo_mode_isolation_issue(env) is None

    env_no_sig = dict(env)
    env_no_sig["WEALL_SIGVERIFY"] = "0"
    assert demo_mode_isolation_issue(env_no_sig) == "sigverify_required_in_controlled_devnet"

    env_no_domain = dict(env)
    env_no_domain["WEALL_STRICT_TX_SIG_DOMAIN"] = "0"
    assert demo_mode_isolation_issue(env_no_domain) == "strict_tx_sig_domain_required_in_controlled_devnet"


def test_controlled_devnet_forbids_demo_and_open_poh_bootstrap() -> None:
    base = {
        "WEALL_MODE": "devnet",
        "WEALL_RUNTIME_PROFILE": "controlled_devnet",
        "WEALL_ENABLE_DEMO_SEED_ROUTE": "0",
        "WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE": "0",
        "WEALL_POH_BOOTSTRAP_OPEN": "0",
        "WEALL_SIGVERIFY": "1",
        "WEALL_STRICT_TX_SIG_DOMAIN": "1",
    }

    env = dict(base)
    env["WEALL_POH_BOOTSTRAP_OPEN"] = "1"
    assert demo_mode_isolation_issue(env) == "poh_open_bootstrap_forbidden_in_controlled_devnet"

    env = dict(base)
    env["WEALL_ENABLE_DEMO_SEED_ROUTE"] = "1"
    assert demo_mode_isolation_issue(env) == "demo_seed_route_forbidden_in_devnet_or_prod"

    env = dict(base)
    env["WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE"] = "1"
    assert demo_mode_isolation_issue(env) == "dev_bootstrap_secret_route_forbidden_in_devnet_or_prod"


def test_devnet_boot_scripts_default_to_controlled_profile() -> None:
    genesis = (REPO_ROOT / "scripts/devnet_boot_genesis_node.sh").read_text(encoding="utf-8")
    joining = (REPO_ROOT / "scripts/devnet_boot_joining_node.sh").read_text(encoding="utf-8")

    for text in (genesis, joining):
        assert 'export WEALL_MODE="${WEALL_MODE:-devnet}"' in text
        assert 'export WEALL_RUNTIME_PROFILE="${WEALL_RUNTIME_PROFILE:-controlled_devnet}"' in text
        assert 'export WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"' in text
        assert 'export WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-0}"' in text
        assert 'export WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE="${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-0}"' in text
        assert 'export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"' in text
        assert 'export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"' in text


def test_controlled_devnet_preflight_script_exists() -> None:
    script = REPO_ROOT / "scripts/devnet_preflight_controlled_profile.sh"
    text = script.read_text(encoding="utf-8")
    assert "controlled-devnet env preflight" in text
    assert "demo_mode_isolation_issue" in text
    assert "WEALL_POH_BOOTSTRAP_OPEN" in text
