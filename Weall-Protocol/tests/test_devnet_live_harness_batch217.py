from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _script(rel: str) -> Path:
    return REPO_ROOT / rel


def test_devnet_live_scripts_are_syntax_valid_and_non_demo_batch217() -> None:
    scripts = [
        "scripts/devnet_bootstrap_live.sh",
        "scripts/devnet_prepare_live_jurors.sh",
        "scripts/devnet_request_live.sh",
        "scripts/devnet_review_live.sh",
        "scripts/devnet_live_session.sh",
        "scripts/devnet_full_live_e2e.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
    ]
    for rel in scripts:
        path = _script(rel)
        proc = subprocess.run(
            ["bash", "-n", str(path)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        text = path.read_text(encoding="utf-8")
        assert "/v1/dev/demo-seed" not in text
        assert "demo-seed" not in text


def test_devnet_live_cli_commands_are_exposed_batch217() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    commands = [
        "bootstrap-live",
        "live-request",
        "live-review",
        "live-session",
        "live-participants",
    ]
    for command in commands:
        proc = subprocess.run(
            [sys.executable, str(_script("scripts/devnet_tx.py")), command, "--help"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert command in proc.stdout


def test_full_onboarding_smoke_can_run_protocol_native_live_flow_batch217() -> None:
    script = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    assert "WEALL_DEVNET_RUN_LIVE" in script
    assert "_run_live_devnet_flow" in script
    assert "devnet_prepare_live_jurors.sh" in script
    assert "devnet_request_live.sh" in script
    assert "devnet_review_live.sh" in script
    assert "devnet_live_session.sh" in script
    assert "Requesting protocol-native Live live PoH through node 1 normal tx flow" in script
    assert "Submitting assigned Live reviewer attendance/verdict txs through normal tx flow" in script
    assert "live-finalization" in script
    assert "Syncing node 2 from node 1 after Live finalization" in script


def test_full_live_wrapper_enables_tier2_and_live_batch217() -> None:
    wrapper = _script("scripts/devnet_full_live_e2e.sh").read_text(encoding="utf-8")
    assert 'WEALL_DEVNET_RUN_TIER2="${WEALL_DEVNET_RUN_TIER2:-1}"' in wrapper
    assert 'WEALL_DEVNET_RUN_LIVE="${WEALL_DEVNET_RUN_LIVE:-1}"' in wrapper
    assert "devnet_full_onboarding_e2e.sh" in wrapper
    assert "/v1/dev/demo-seed" not in wrapper


def test_controlled_devnet_uses_partial_live_panel_not_open_bootstrap_batch217() -> None:
    genesis = _script("scripts/devnet_boot_genesis_node.sh").read_text(encoding="utf-8")
    joining = _script("scripts/devnet_boot_joining_node.sh").read_text(encoding="utf-8")
    assert 'WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"' in genesis
    assert 'WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"' in joining
    assert 'WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED="${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED:-1}"' in genesis
    assert 'WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED="${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED:-1}"' in joining
    assert "live_partial_panels=${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED}" in genesis
    assert "live_partial_panels=${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED}" in joining


def test_live_devnet_flow_uses_normal_txs_not_operator_mutation_batch217() -> None:
    files = [
        "scripts/devnet_bootstrap_live.sh",
        "scripts/devnet_prepare_live_jurors.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
        "scripts/devnet_full_live_e2e.sh",
        "scripts/devnet_tx.py",
    ]
    combined = "\n".join(_script(rel).read_text(encoding="utf-8") for rel in files)
    assert "GENESIS_REVIEWER_ACCOUNT" in combined
    assert "POH_BOOTSTRAP_TIER2_GRANT" in _script("scripts/devnet_tx.py").read_text(encoding="utf-8")
    assert "/poh/operator/live/init" not in combined
    assert "/poh/operator/live/finalize" not in combined
    assert "WEALL_ENABLE_OPERATOR_POH" not in combined
