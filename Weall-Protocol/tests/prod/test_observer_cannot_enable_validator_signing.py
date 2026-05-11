from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run_preflight(extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "WEALL_MODE": "prod",
        "WEALL_CHAIN_MANIFEST_PATH": str(ROOT / "configs" / "chains" / "weall-genesis.json"),
        "WEALL_OBSERVER_MODE": "1",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
        "WEALL_BFT_ENABLED": "0",
        "WEALL_SERVICE_ROLES": "",
    }
    env.update(extra_env)
    return subprocess.run(
        ["bash", "scripts/prod_node_preflight.sh"],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def test_observer_boot_refuses_validator_signing() -> None:
    result = _run_preflight({"WEALL_VALIDATOR_SIGNING_ENABLED": "1"})
    assert result.returncode != 0
    assert "WEALL_OBSERVER_MODE=1 cannot be combined with WEALL_VALIDATOR_SIGNING_ENABLED=1" in result.stdout


def test_observer_boot_refuses_bft_enabled() -> None:
    result = _run_preflight({"WEALL_BFT_ENABLED": "1"})
    assert result.returncode != 0
    assert "WEALL_OBSERVER_MODE=1 cannot be combined with WEALL_BFT_ENABLED=1" in result.stdout


def test_observer_boot_refuses_validator_role_and_account() -> None:
    result = _run_preflight({"WEALL_SERVICE_ROLES": "validator"})
    assert result.returncode != 0
    assert "observer mode cannot request validator service role" in result.stdout

    result = _run_preflight({"WEALL_VALIDATOR_ACCOUNT": "@observer"})
    assert result.returncode != 0
    assert "observer mode must not set WEALL_VALIDATOR_ACCOUNT" in result.stdout


def test_production_preflight_refuses_unsafe_demo_and_authority_key_paths() -> None:
    cases = {
        "WEALL_UNSAFE_DEV": "WEALL_UNSAFE_DEV must not be set",
        "WEALL_GENESIS_MODE": "WEALL_GENESIS_MODE must not be set",
        "WEALL_ENABLE_DEMO_SEED_ROUTE": "WEALL_ENABLE_DEMO_SEED_ROUTE must not be set",
        "WEALL_AUTHORITY_SIGNER_PRIVKEY_FILE": "authority snapshot signer private key path",
        "WEALL_AUTHORITY_PRIVKEY_FILE": "authority private key path",
        "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY_FILE": "legacy authority signer private key path",
    }
    for key, expected in cases.items():
        result = _run_preflight({key: "/tmp/not-for-observer"})
        assert result.returncode != 0, key
        assert expected in result.stdout
