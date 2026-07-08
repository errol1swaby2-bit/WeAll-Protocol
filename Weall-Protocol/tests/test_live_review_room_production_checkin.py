from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "web" / "src" / "pages" / "LiveVerificationRoom.tsx"


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _function_body(src: str, name: str) -> str:
    needle = f"async function {name}("
    start_idx = src.find(needle)
    assert start_idx >= 0, f"missing {name}"
    brace_idx = src.find("{", start_idx)
    assert brace_idx >= 0, f"missing {name} body"
    start = brace_idx + 1
    depth = 1
    idx = start
    while idx < len(src) and depth:
        char = src[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        idx += 1
    assert depth == 0, f"could not parse {name}"
    return src[start : idx - 1]


def test_live_review_join_records_chain_attendance_before_room_presence_or_media() -> None:
    src = _page()
    body = _function_body(src, "checkIntoRoom")

    assert "pohLiveTxJurorAccept" not in body
    assert "Accept review first from the Review Center" in body
    assert "pohLiveTxAttendance" in body
    assert "waitForLiveJurorState(\"Live room attendance\"" in body
    assert "await updatePresence(\"joined\")" not in body
    assert "tryUpdatePresence(\"joined\")" in body

    attendance_idx = body.index("pohLiveTxAttendance")
    media_idx = body.index("ensureP2PRoomStarted")
    external_presence_idx = body.index("tryUpdatePresence(\"joined\")")

    assert attendance_idx < media_idx < external_presence_idx

def test_p2p_room_presence_is_recorded_before_local_media_but_running_requires_media() -> None:
    body = _function_body(_page(), "ensureP2PRoomStarted")

    presence_idx = body.index("await updatePresence(\"joined\")")
    media_idx = body.index("await ensureLocalP2PMedia()")
    running_idx = body.index("setP2pRunning(true)")
    hello_idx = body.index("sendWebRTCSignal({ type: \"hello\" })")

    assert presence_idx < media_idx < running_idx < hello_idx
    assert "room presence recorded; local media unavailable" in body


def test_inbound_webrtc_signals_do_not_require_local_media_capture_first() -> None:
    body = _function_body(_page(), "handleWebRTCSignal")

    assert "getOrCreatePeerConnection(from)" in body
    assert "ensureLocalP2PMedia" not in body
    assert "setRemoteDescription({ type: \"offer\"" in body
    assert "createAnswer()" in body


def test_missing_media_recovery_defers_offers_without_breaking_signal_polling() -> None:
    body = _function_body(_page(), "recoverMissingPeerMedia")

    assert "try {" in body
    assert "await createOfferForPeer(remote, { reason });" in body
    assert "offer deferred:" in body
    assert "waiting for local media" in body
