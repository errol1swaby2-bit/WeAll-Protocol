from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NESTED = ROOT / "Weall-Protocol"
WEB = ROOT / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_live_room_default_is_decentralized_p2p_descriptor_batch406() -> None:
    live = _read(WEB / "src" / "lib" / "liveRoom.ts")

    assert 'transport: "p2p-webrtc"' in live
    assert 'authority: "weall-chain"' in live
    assert 'signaling: "case-scoped-presence"' in live
    assert 'relay_policy: "community-relay-fallback-only"' in live
    assert 'identity_protection: "subject-and-assigned-reviewers-only"' in live
    assert "liveRoomDescriptorFromCommitment" in live
    assert "liveRoomDescriptorText" in live
    assert 'return raw === "centralized-url" ? "centralized-url" : "p2p"' in live
    assert 'VITE_WEALL_ALLOW_CENTRALIZED_LIVE_ROOM_URL' in live


def test_local_rehearsal_defaults_to_p2p_live_transport_batch406() -> None:
    script = _read(NESTED / "scripts" / "devnet_local_two_frontend_rehearsal.sh")

    assert 'LIVE_ROOM_TRANSPORT_MODE="${VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE:-p2p}"' in script
    assert 'LIVE_ROOM_BASE_URL="${VITE_WEALL_LIVE_ROOM_BASE_URL:-}"' in script
    assert 'export VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE="${LIVE_ROOM_TRANSPORT_MODE}"' in script
    assert 'live_room_transport=${LIVE_ROOM_TRANSPORT_MODE}' in script
    assert 'controlled-live-room' not in script
    assert 'https://meet.jit.si' not in script


def test_live_room_pages_surface_p2p_descriptor_without_central_url_batch406() -> None:
    room = _read(WEB / "src" / "pages" / "LiveVerificationRoom.tsx")
    account = _read(WEB / "src" / "pages" / "AccountVerificationPage.tsx")
    juror = _read(WEB / "src" / "pages" / "JurorDashboard.tsx")

    for src in (room, account, juror):
        assert "liveRoomDescriptorText" in src
        assert "P2P room descriptor" in src or "peer-to-peer room descriptor" in src

    assert "Use the decentralized P2P room descriptor below" in room
    assert "No centralized room URL is required" in account
    assert "no centralized room URL is required" in juror


def test_csp_no_longer_allows_arbitrary_https_frames_for_live_room_batch406() -> None:
    vite = _read(WEB / "vite.config.ts")

    assert "frame-src 'self' http://127.0.0.1:* http://localhost:*;" in vite
    assert "frame-src 'self' http://127.0.0.1:* http://localhost:* https:;" not in vite
