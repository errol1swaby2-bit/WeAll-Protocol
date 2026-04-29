from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _script(rel: str) -> Path:
    return REPO_ROOT / rel


def test_devnet_tier3_scripts_are_syntax_valid_and_non_demo_batch217() -> None:
    scripts = [
        "scripts/devnet_bootstrap_tier3.sh",
        "scripts/devnet_prepare_tier3_jurors.sh",
        "scripts/devnet_request_tier3.sh",
        "scripts/devnet_review_tier3.sh",
        "scripts/devnet_tier3_session.sh",
        "scripts/devnet_full_tier3_e2e.sh",
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


def test_devnet_tier3_cli_commands_are_exposed_batch217() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    commands = [
        "bootstrap-tier3",
        "tier3-request",
        "tier3-review",
        "tier3-session",
        "tier3-participants",
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


def test_full_onboarding_smoke_can_run_protocol_native_tier3_flow_batch217() -> None:
    script = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    assert "WEALL_DEVNET_RUN_TIER3" in script
    assert "_run_tier3_devnet_flow" in script
    assert "devnet_prepare_tier3_jurors.sh" in script
    assert "devnet_request_tier3.sh" in script
    assert "devnet_review_tier3.sh" in script
    assert "devnet_tier3_session.sh" in script
    assert "Requesting protocol-native Tier-3 live PoH through node 1 normal tx flow" in script
    assert "Submitting assigned Tier-3 reviewer attendance/verdict txs through normal tx flow" in script
    assert "tier3-finalization" in script
    assert "Syncing node 2 from node 1 after Tier-3 finalization" in script


def test_full_tier3_wrapper_enables_tier2_and_tier3_batch217() -> None:
    wrapper = _script("scripts/devnet_full_tier3_e2e.sh").read_text(encoding="utf-8")
    assert 'WEALL_DEVNET_RUN_TIER2="${WEALL_DEVNET_RUN_TIER2:-1}"' in wrapper
    assert 'WEALL_DEVNET_RUN_TIER3="${WEALL_DEVNET_RUN_TIER3:-1}"' in wrapper
    assert "devnet_full_onboarding_e2e.sh" in wrapper
    assert "/v1/dev/demo-seed" not in wrapper


def test_controlled_devnet_bootstrap_window_supports_tier3_reviewer_setup_batch217() -> None:
    genesis = _script("scripts/devnet_boot_genesis_node.sh").read_text(encoding="utf-8")
    joining = _script("scripts/devnet_boot_joining_node.sh").read_text(encoding="utf-8")
    assert 'WEALL_POH_BOOTSTRAP_MAX_HEIGHT="${WEALL_POH_BOOTSTRAP_MAX_HEIGHT:-500}"' in genesis
    assert 'WEALL_POH_BOOTSTRAP_MAX_HEIGHT="${WEALL_POH_BOOTSTRAP_MAX_HEIGHT:-500}"' in joining
    assert "poh_bootstrap_max_height=${WEALL_POH_BOOTSTRAP_MAX_HEIGHT}" in genesis
    assert "poh_bootstrap_max_height=${WEALL_POH_BOOTSTRAP_MAX_HEIGHT}" in joining


def test_tier3_devnet_flow_uses_normal_txs_not_operator_mutation_batch217() -> None:
    files = [
        "scripts/devnet_bootstrap_tier3.sh",
        "scripts/devnet_prepare_tier3_jurors.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
        "scripts/devnet_full_tier3_e2e.sh",
        "scripts/devnet_tx.py",
    ]
    combined = "\n".join(_script(rel).read_text(encoding="utf-8") for rel in files)
    assert "POH_BOOTSTRAP_TIER3_GRANT" in combined
    assert "/v1/tx/submit" in combined
    assert "/poh/operator/tier3/init" not in combined
    assert "/poh/operator/tier3/finalize" not in combined
    assert "WEALL_ENABLE_OPERATOR_POH" not in combined
