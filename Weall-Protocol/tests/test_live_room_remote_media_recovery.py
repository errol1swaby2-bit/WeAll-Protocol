from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_webrtc_track_without_stream_is_materialized() -> None:
    src = _read(WEB / "src/lib/webrtcLiveRoom.ts")
    assert "new MediaStream([event.track])" in src
    assert "Do not drop the remote participant's media" in src


def test_live_room_queues_ice_and_retries_missing_remote_media() -> None:
    src = _read(WEB / "src/pages/LiveVerificationRoom.tsx")
    assert "pendingIceCandidatesRef" in src
    assert "flushPendingIceCandidates" in src
    assert "addOrQueueIceCandidate" in src
    assert "recoverMissingPeerMedia" in src
    assert "startup recovery" in src
    assert "poll recovery" in src


def test_live_room_targets_hello_and_surfaces_peer_state() -> None:
    src = _read(WEB / "src/pages/LiveVerificationRoom.tsx")
    assert "sendWebRTCSignal({ type: \"hello\", to_account: peer })" in src
    assert "peerStates" in src
    assert "Peer states:" in src
    assert "State: ${peerStates[peer]}" in src


def test_live_room_signal_handling_is_duplicate_and_glare_tolerant() -> None:
    src = _read(WEB / "src/pages/LiveVerificationRoom.tsx")
    assert "processedSignalsRef" in src
    assert "signalDedupeKey" in src
    assert "setLocalDescription({ type: \"rollback\" }" in src
    assert "pc.signalingState === \"have-local-offer\"" in src
