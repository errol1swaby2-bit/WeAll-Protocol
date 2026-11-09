from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parents[0] / "web" / "src"


def test_observer_tx_status_does_not_mark_local_tx_queue_tx_synced() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "tx.py").read_text(
        encoding="utf-8"
    )

    assert "observer_local_confirmed_not_upstream_synced" in src
    assert "Never convert a" in src and "local tx-index hit into upstream confirmation" in src
    assert '"status": "confirmed" if upstream_confirmed else "local_confirmed"' in src
    assert '"local_state_synced": local_synced' in src
    assert (
        '_update_tx_queue_record(t, {"upstream_status": "confirmed", "confirmed_height": int(idx.get("height") or 0)'
        not in src
    )


def test_live_request_pending_room_does_not_impersonate_synced_case() -> None:
    page = (WEB / "pages" / "AccountVerificationPage.tsx").read_text(encoding="utf-8")
    room = (WEB / "pages" / "LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert "requireLocalStateSynced: false" in page
    assert "acceptAccepted: true" in page
    assert "pending_case_visibility: !visibleCaseId" in page
    assert "waitForLiveCaseIdVisible(acct, expectedCaseId, base, headers" in page
    assert "resultCaseId && resultCaseId === expectedCaseId" in page
    assert "casePendingSync" in room
    assert "!!account && (isSubject || !!myJuror)" in room
    assert "Live request accepted. Waiting for the live case and session to sync" in room
