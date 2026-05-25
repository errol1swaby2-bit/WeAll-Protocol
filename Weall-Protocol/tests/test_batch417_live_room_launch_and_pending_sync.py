from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web" / "src"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_live_request_uses_sequenced_nonce_and_opens_expected_room_batch417() -> None:
    page = _read(WEB / "pages" / "AccountVerificationPage.tsx")
    body = page.split("async function submitLiveRequest()", 1)[1].split("const asyncSubmitCheck", 1)[0]

    assert "Batch 417: use the sequenced signer path" in body
    assert "submitSignedTxInSequence" in body
    assert "expectedLiveCaseIdFromNonce" in page
    assert "poh_live:${acct}:${n}" in page
    assert "pending_case_visibility" in body
    assert "requireLocalStateSynced: false" in body
    assert "acceptAccepted: true" in body
    assert 'nav(`/verification/live/${encodeURIComponent(visibleCaseId)}`)' in body


def test_live_room_polls_when_navigated_before_case_sync_batch417() -> None:
    room = _read(WEB / "pages" / "LiveVerificationRoom.tsx")

    assert "casePendingSync" in room
    assert "live_case_not_found" in room
    assert "Keep polling instead of stranding the user on a dead room page" in room
    assert "window.setInterval" in room
    assert "Live request accepted. Waiting for the live case and session to sync into this frontend" in room


def test_reviewer_queue_surfaces_pending_live_sessions_before_assignment_batch417() -> None:
    dashboard = _read(WEB / "pages" / "JurorDashboard.tsx")

    assert "livePendingSessions" in dashboard
    assert "Live verification request/session records are visible" in dashboard
    assert "but no reviewer assignment has reached this queue yet" in dashboard
    assert "Pending live session" in dashboard
    assert "Open live room" in dashboard
