from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_local_rehearsal_waits_for_frontend_shell_not_only_backend_proxy() -> None:
    src = _read(ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh")

    assert "_wait_frontend_root()" in src
    assert "timed out waiting for frontend index" in src
    assert "proxied /v1/status alone can pass while the browser still cannot load the app" in src
    assert "_wait_frontend_root" in src
    assert "OBSERVER_FRONTEND_PORT" in src
    assert "GENESIS_FRONTEND_PORT" in src
    assert "WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST" in src or "--host 0.0.0.0" in src


def test_local_rehearsal_frontend_ports_are_strict() -> None:
    src = _read(ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh")

    assert '--port "${OBSERVER_FRONTEND_PORT}" --strictPort --force' in src
    assert '--port "${GENESIS_FRONTEND_PORT}" --strictPort --force' in src
