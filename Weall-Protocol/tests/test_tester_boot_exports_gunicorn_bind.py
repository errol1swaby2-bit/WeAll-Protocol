from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tester_node_boot_exports_gunicorn_bind() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert 'export GUNICORN_BIND="${GUNICORN_BIND:-0.0.0.0:${API_PORT}}"' in script
    assert "run_node.sh binds via GUNICORN_BIND" in script
