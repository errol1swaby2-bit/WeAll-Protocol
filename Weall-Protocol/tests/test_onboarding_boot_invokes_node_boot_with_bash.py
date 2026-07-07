from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_onboarding_boot_invokes_node_boot_with_bash() -> None:
    script = (ROOT / "scripts" / "boot_onboarding_node.sh").read_text(encoding="utf-8")

    assert 'exec bash "${SCRIPT_DIR}/boot_weall_node.sh"' in script
    assert 'exec "${SCRIPT_DIR}/boot_weall_node.sh"' not in script
