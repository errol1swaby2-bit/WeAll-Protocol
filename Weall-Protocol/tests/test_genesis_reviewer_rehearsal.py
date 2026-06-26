from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_controlled_devnet_does_not_enable_open_bootstrap_for_rehearsal() -> None:
    genesis = _text("scripts/devnet_boot_genesis_node.sh")
    joining = _text("scripts/devnet_boot_joining_node.sh")
    assert 'WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"' in genesis
    assert 'WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"' in joining
    assert "poh_bootstrap_open=${WEALL_POH_BOOTSTRAP_OPEN}" in genesis
    assert "poh_bootstrap_open=${WEALL_POH_BOOTSTRAP_OPEN}" in joining


def test_live_reviewer_setup_is_genesis_bound_not_runtime_self_grant() -> None:
    prepare = _text("scripts/devnet_prepare_live_jurors.sh")
    assert "GENESIS_REVIEWER_ACCOUNT" in prepare
    assert "Deterministic genesis-bound Live reviewer ready" in prepare
    assert "No open bootstrap or runtime reviewer self-grant was used" in prepare
    assert "devnet_bootstrap_live.sh" not in prepare
    assert "POH_BOOTSTRAP_TIER2_GRANT" not in prepare
    assert "WEALL_POH_BOOTSTRAP_OPEN=1" not in prepare


def test_full_onboarding_uses_genesis_reviewer_and_partial_live_panel() -> None:
    onboarding = _text("scripts/devnet_full_onboarding_e2e.sh")
    genesis = _text("scripts/devnet_boot_genesis_node.sh")
    assert "Verifying deterministic genesis-bound Live reviewer authority" in onboarding
    assert "WEALL_GENESIS_REVIEWER_ACCOUNT=\"${OPERATOR_ACCOUNT}\"" in onboarding
    assert "1 <= len(jurors) <= 10" in onboarding
    assert 'WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED="${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED:-1}"' in genesis
    assert 'WEALL_POH_LIVE_PASS_THRESHOLD_NUM="${WEALL_POH_LIVE_PASS_THRESHOLD_NUM:-1}"' in genesis


def test_modified_rehearsal_scripts_are_syntax_valid() -> None:
    for rel in [
        "scripts/devnet_prepare_live_jurors.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
        "scripts/devnet_boot_genesis_node.sh",
        "scripts/devnet_boot_joining_node.sh",
    ]:
        proc = subprocess.run(
            ["bash", "-n", str(ROOT / rel)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, f"{rel}: {proc.stderr}"
