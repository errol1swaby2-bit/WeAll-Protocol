from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parents[0] / "web" / "src"


def test_observer_tx_status_does_not_mark_local_outbox_tx_synced_batch396() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "tx.py").read_text(encoding="utf-8")

    assert "observer_local_confirmed_not_upstream_synced" in src
    assert "Never convert a" in src and "local tx-index hit into upstream confirmation" in src
    assert '"status": "confirmed" if upstream_confirmed else "local_confirmed"' in src
    assert '"local_state_synced": local_synced' in src
    assert '_update_tx_outbox_record(t, {"upstream_status": "confirmed", "confirmed_height": int(idx.get("height") or 0)' not in src


def test_live_request_frontend_requires_local_state_synced_before_room_route_batch396() -> None:
    page = (WEB / "pages" / "AccountVerificationPage.tsx").read_text(encoding="utf-8")

    assert "Live verification request was not confirmed on genesis and synced back to the observer yet" in page
    assert "requireLocalStateSynced: true" in page
    assert "waitForLiveCaseIdVisible" in page
