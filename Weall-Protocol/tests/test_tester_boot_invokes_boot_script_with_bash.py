from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tester_node_boot_invokes_onboarding_script_with_bash() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert 'exec bash "${ROOT_DIR}/scripts/boot_onboarding_node.sh"' in script
    assert 'exec "${ROOT_DIR}/scripts/boot_onboarding_node.sh"' not in script
