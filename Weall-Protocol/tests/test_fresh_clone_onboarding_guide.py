from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "NEW_NODE_OPERATOR_QUICKSTART.md"
ONBOARDING = ROOT / "scripts" / "boot_onboarding_node.sh"
REHEARSAL = ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh"
TESTER = ROOT / "scripts" / "weall_tester_node.sh"


def test_documented_low_level_onboarding_launcher_is_executable() -> None:
    assert stat.S_IMODE(ONBOARDING.stat().st_mode) & stat.S_IXUSR, (
        "FCO-001: documented ./scripts/boot_onboarding_node.sh "
        "must be executable in a fresh Git checkout"
    )


def test_fresh_clone_quickstart_describes_both_real_boot_paths() -> None:
    guide = GUIDE.read_text(encoding="utf-8")
    for required in (
        "requirements-dev.lock",
        "python -m pip install -e . --no-deps",
        "bash scripts/devnet_local_two_frontend_rehearsal.sh",
        "bash scripts/weall_tester_node.sh",
        "WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE",
        "operator-provided",
        "disposable",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "docs/REVIEWER_LAN_REHEARSAL_QUICKSTART.md",
        "upstream_not_confirmed",
    ):
        assert required in guide, required
    assert REHEARSAL.is_file()
    assert TESTER.is_file()


def test_bare_onboarding_boot_still_rejects_missing_public_bundle() -> None:
    # Reproduce the clean-clone failure without accidentally inheriting a
    # developer's permissive WEALL_* variables or touching a running node.
    env = {key: value for key, value in os.environ.items() if not key.startswith("WEALL_")}
    result = subprocess.run(
        ["bash", str(ONBOARDING)],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE" in result.stderr
