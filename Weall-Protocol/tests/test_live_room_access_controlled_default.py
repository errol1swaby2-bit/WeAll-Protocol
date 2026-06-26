from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = BACKEND_ROOT.parent
WEB_SRC = OUTER_ROOT / "web" / "src"


def test_live_room_rejects_public_jitsi_and_defaults_to_p2p() -> None:
    live = (WEB_SRC / "lib" / "liveRoom.ts").read_text(encoding="utf-8")

    assert "meet.jit.si" in live
    assert "return false" in live
    assert "Optional hosted URL transport is explicit and access-controlled" in live
    assert "centralized URL transport is a compatibility escape hatch" not in live
    assert "p2p-webrtc" in live

    script = (BACKEND_ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(
        encoding="utf-8"
    )

    assert "controlled-live-room" not in script
    assert "https://meet.jit.si" not in script
    assert "LIVE_ROOM_TRANSPORT_MODE" in script
