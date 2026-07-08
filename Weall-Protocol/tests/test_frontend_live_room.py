from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def test_frontend_live_room_route_and_page_exist() -> None:
    app = (OUTER / "web/src/App.tsx").read_text(encoding="utf-8")
    router = (OUTER / "web/src/lib/router.ts").read_text(encoding="utf-8")
    page = (OUTER / "web/src/pages/LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert "./pages/LiveVerificationRoom" in app
    assert 'case "/verification/live/:caseId"' in app
    assert '"/verification/live/:caseId"' in router
    assert 'r.startsWith("/live/")' not in router
    assert "iframe" in page
    assert "POH_LIVE_ATTENDANCE_MARK" not in page  # uses backend skeleton helpers, not hand-built tx strings
    assert "pohLiveTxAttendance" in page
    assert "pohLiveTxVerdict" in page
    assert "pohOperatorLiveFinalize" in page
    assert "transport-only" in page or "transport only" in page


def test_frontend_live_room_presence_api_client_exists() -> None:
    api = (OUTER / "web/src/api/weall.ts").read_text(encoding="utf-8")
    page = (OUTER / "web/src/pages/LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert "pohLiveSessionPresence" in api
    assert "pohLiveSessionPresenceUpdate" in api
    assert "/v1/poh/live/session/${encodeURIComponent(sessionId)}/presence" in api
    assert "camera_enabled" in page
    assert "mic_enabled" in page
    assert "presence" in page


def test_existing_verification_surfaces_link_to_live_room() -> None:
    account_page = (OUTER / "web/src/pages/AccountVerificationPage.tsx").read_text(encoding="utf-8")
    juror_page = (OUTER / "web/src/pages/JurorDashboard.tsx").read_text(encoding="utf-8")

    assert "Open live verification room" in account_page
    assert "Accept live review assignment" in juror_page
    assert "/verification/live/" in juror_page
    assert "/verification/live/" in account_page
    assert "/verification/live/" in juror_page


def test_frontend_live_room_does_not_persist_operator_token() -> None:
    page = (OUTER / "web/src/pages/LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert "weall.operator.poh.token" not in page
    assert "localStorage.getItem" not in page
    assert "localStorage.setItem" not in page
    assert "sessionStorage" not in page
    assert 'type="password"' in page
