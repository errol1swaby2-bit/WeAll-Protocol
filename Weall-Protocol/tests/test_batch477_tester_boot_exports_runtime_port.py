from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tester_node_boot_exports_runtime_port_batch477() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert 'export WEALL_API_PORT="${API_PORT}"' in script
    assert 'export PORT="${API_PORT}"' in script
    assert "bridge tester-selected API port into the runtime bind variable" in script
