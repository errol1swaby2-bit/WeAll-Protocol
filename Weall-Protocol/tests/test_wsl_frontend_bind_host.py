from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh"


def test_local_rehearsal_binds_vite_to_loopback_not_lan() -> None:
    """WSL Windows-browser forwarding is a manual check, not permission to expose keys on LAN."""
    src = LAUNCHER.read_text(encoding="utf-8")

    assert 'FRONTEND_BIND_HOST="${WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST:-127.0.0.1}"' in src
    assert 'FRONTEND_PUBLIC_HOST="${WEALL_LOCAL_REHEARSAL_FRONTEND_PUBLIC_HOST:-127.0.0.1}"' in src
    assert 'case "${FRONTEND_BIND_HOST}" in' in src
    assert 'case "${FRONTEND_PUBLIC_HOST}" in' in src
    assert '--host "${FRONTEND_BIND_HOST}"' in src
    assert "--strictPort --force" in src
    assert "vite .*--port ${OBSERVER_FRONTEND_PORT}" in src
    assert "vite .*--port ${GENESIS_FRONTEND_PORT}" in src


def test_local_rehearsal_rejects_remote_frontend_bind_before_starting_services() -> None:
    # Fail before process termination, runtime initialization, or any reset.
    for override, value in (
        ("WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST", "0.0.0.0"),
        ("WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST", "192.168.1.2"),
        ("WEALL_LOCAL_REHEARSAL_FRONTEND_PUBLIC_HOST", "192.168.1.2"),
    ):
        env = {k: v for k, v in os.environ.items() if not k.startswith("WEALL_")}
        env[override] = value
        result = subprocess.run(
            ["bash", str(LAUNCHER)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert result.returncode == 2, (override, result.stdout, result.stderr)
        assert "loopback-only frontend" in result.stderr
