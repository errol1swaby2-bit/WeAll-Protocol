from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_account_register_tx_skeleton_route_batch209() -> None:
    app = create_app(boot_runtime=False)
    client = TestClient(app)

    resp = client.post(
        "/v1/accounts/tx/register",
        json={"account_id": "@new-human", "pubkey": "abcd1234"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["tx"]["tx_type"] == "ACCOUNT_REGISTER"
    assert body["tx"]["signer_hint"] == "@new-human"
    assert body["tx"]["payload"] == {"pubkey": "abcd1234"}


def test_devnet_onboarding_scripts_are_syntax_valid_batch209() -> None:
    scripts = [
        "scripts/devnet_create_account.sh",
        "scripts/devnet_submit_tx_node1.sh",
        "scripts/devnet_submit_tx_node2.sh",
        "scripts/devnet_wait_tx.sh",
        "scripts/devnet_account_status.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
    ]
    for rel in scripts:
        proc = subprocess.run(
            ["bash", "-n", str(REPO_ROOT / rel)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr


def test_devnet_tx_helper_cli_help_batch209() -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/devnet_tx.py"), "--help"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Controlled-devnet transaction helper" in proc.stdout


def test_devnet_scripts_do_not_call_demo_seed_batch209() -> None:
    scripts = [
        "scripts/devnet_create_account.sh",
        "scripts/devnet_submit_tx_node1.sh",
        "scripts/devnet_submit_tx_node2.sh",
        "scripts/devnet_wait_tx.sh",
        "scripts/devnet_account_status.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
        "scripts/devnet_tx.py",
    ]
    for rel in scripts:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "/v1/dev/demo-seed" not in text
        assert "WEALL_ENABLE_DEMO_SEED_ROUTE" not in text
