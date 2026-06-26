from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_boot_weall_invokes_run_node_with_bash_batch475() -> None:
    script = (ROOT / "scripts" / "boot_weall_node.sh").read_text(encoding="utf-8")

    assert "run_node.sh" in script
    assert 'exec bash "$(dirname "$0")/run_node.sh"' in script
    assert 'exec "$(dirname "$0")/run_node.sh"' not in script
