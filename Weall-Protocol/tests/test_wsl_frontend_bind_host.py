from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_local_rehearsal_binds_vite_for_wsl_windows_browsers_batch403() -> None:
    src = (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")

    assert "FRONTEND_BIND_HOST=" in src
    assert "WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST:-0.0.0.0" in src
    assert "FRONTEND_PUBLIC_HOST=" in src
    assert "--host \"${FRONTEND_BIND_HOST}\"" in src
    assert "--strictPort --force" in src
    assert "vite .*--port ${OBSERVER_FRONTEND_PORT}" in src
    assert "vite .*--port ${GENESIS_FRONTEND_PORT}" in src
