from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tester_node_boot_sets_explicit_local_cors_batch476() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert "WEALL_CORS_ORIGINS" in script
    assert "http://127.0.0.1:${FRONTEND_PORT}" in script
    assert "http://localhost:${FRONTEND_PORT}" in script
    assert "production-mode tester observer boot must set explicit local CORS" in script
