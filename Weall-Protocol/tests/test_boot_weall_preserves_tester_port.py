from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_boot_weall_preserves_tester_api_port_batch478() -> None:
    script = (ROOT / "scripts" / "boot_weall_node.sh").read_text(encoding="utf-8")

    assert "WEALL_API_PORT" in script
    assert 'export PORT="${WEALL_API_PORT}"' in script
    assert "preserve tester-selected API bind port through final boot wrapper" in script
    assert 'exec bash "$(dirname "$0")/run_node.sh"' in script
