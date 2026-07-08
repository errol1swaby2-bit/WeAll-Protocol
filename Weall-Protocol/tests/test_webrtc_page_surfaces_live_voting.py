from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"


def test_webrtc_page_surfaces_live_voting_inside_video_room() -> None:
    src = (WEB / "src" / "pages" / "LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert 'data-testid="webrtc-live-voting"' in src
    assert "In-call chain voting" in src
    assert "Reviewer vote inside the WebRTC room" in src
    assert "Use these controls without leaving the WebRTC page" in src
    assert "Approve live verification" in src
    assert "Reject live verification" in src

    video_idx = src.index("Conference feed")
    voting_idx = src.index('data-testid="webrtc-live-voting"')
    participant_idx = src.index("Participant state")

    assert video_idx < voting_idx < participant_idx


def test_webrtc_voting_copy_keeps_video_transport_non_authoritative() -> None:
    src = (WEB / "src" / "pages" / "LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert "The video room remains transport only" in src
    assert "acceptance and attendance steps are both reflected on-chain" in src
    assert "on-chain attendance" in src


def test_webrtc_join_action_records_attendance_after_separate_acceptance() -> None:
    src = (WEB / "src" / "pages" / "LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert "waitForLiveJurorState" in src
    assert "Accept review first" in src
    assert "Join call and check in" in src
    assert "Live room attendance" in src
    assert "acceptance and attendance steps are both reflected on-chain" in src
    assert ">Accept review<" not in src
    assert ">Record attendance<" not in src
    assert "Follow the button label for the next milestone" in src

    assert "pohLiveTxJurorAccept" not in src
    assert "pohLiveTxAttendance" in src
