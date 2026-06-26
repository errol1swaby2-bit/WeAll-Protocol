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
    assert "Voting unlocks only for an assigned interacting reviewer" in src
    assert "on-chain attendance" in src
