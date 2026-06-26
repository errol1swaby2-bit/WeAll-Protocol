from __future__ import annotations

from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
ROOT = REPO.parent


def test_local_rehearsal_waits_for_observer_local_state_before_frontend_boot() -> None:
    src = (REPO / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")
    assert "_wait_tx_local_state_synced()" in src
    assert "/v1/observer/edge/reconcile/" in src
    assert "OBSERVER_REGISTER_TX_ID" in src
    assert src.index("_wait_tx_local_state_synced") < src.index("Starting observer frontend")
    assert "signature verification failed" in src


def test_dev_bootstrap_login_uses_manifest_api_base_for_secret_and_login() -> None:
    src = (ROOT / "web" / "src" / "pages" / "LoginPage.tsx").read_text(encoding="utf-8")
    assert "const apiBase = manifestApiBase(devManifest, apiBaseInput)" in src
    assert 'fetchDevBootstrapSecret(String(devManifest.account || ""), apiBase)' in src
    assert "setApiBase(apiBase)" in src
    assert "base: apiBase" in src
    assert "ttlSeconds" in src
