from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def test_frontend_has_decentralized_p2p_live_room_transport_only_copy() -> None:
    live_room = (OUTER / "web/src/lib/liveRoom.ts").read_text(encoding="utf-8")
    account_page = (OUTER / "web/src/pages/AccountVerificationPage.tsx").read_text(encoding="utf-8")
    juror_page = (OUTER / "web/src/pages/JurorDashboard.tsx").read_text(encoding="utf-8")
    env_example = (OUTER / "web/.env.example").read_text(encoding="utf-8")

    assert "VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE" in live_room
    assert "p2p-webrtc" in live_room
    assert "weall-live-" in live_room
    assert "transport only" in live_room
    assert "liveRoomUrlFromCommitment" in account_page
    assert "liveRoomUrlFromCommitment" in juror_page
    assert "VITE_WEALL_LIVE_ROOM_BASE_URL" in env_example


def test_frontend_async_evidence_payload_includes_reviewable_video_reference() -> None:
    account_page = (OUTER / "web/src/pages/AccountVerificationPage.tsx").read_text(encoding="utf-8")
    juror_page = (OUTER / "web/src/pages/JurorDashboard.tsx").read_text(encoding="utf-8")
    api = (OUTER / "web/src/api/weall.ts").read_text(encoding="utf-8")

    for marker in (
        "public_evidence_id",
        "evidence_cid",
        "fresh_recorded_video_v1",
    ):
        assert marker in account_page

    assert "reviewable_evidence" in juror_page
    assert "evidence_commitments" in juror_page
    assert "pohLiveMyCases" in api
    assert "/v1/poh/live/my-cases" in api
