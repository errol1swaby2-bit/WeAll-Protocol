from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NESTED = ROOT / "Weall-Protocol"
WEB = ROOT / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_auth_headers_normalize_session_account_before_comparing() -> None:
    src = _read(WEB / "src" / "auth" / "session.ts")
    assert "const sessionAccount = normalizeAccount(s.account);" in src
    assert "const acct = normalizeAccount(account || sessionAccount);" in src
    assert "acct !== sessionAccount" in src
    assert '"x-weall-account": sessionAccount' in src


def test_live_room_opens_external_by_default_and_embed_is_opt_in() -> None:
    live = _read(WEB / "src" / "lib" / "liveRoom.ts")
    room = _read(WEB / "src" / "pages" / "LiveVerificationRoom.tsx")
    script = _read(NESTED / "scripts" / "devnet_local_two_frontend_rehearsal.sh")

    assert "export function liveRoomEmbedEnabled" in live
    assert "VITE_WEALL_LIVE_ROOM_EMBED" in live
    assert 'LIVE_ROOM_EMBED="${VITE_WEALL_LIVE_ROOM_EMBED:-0}"' in script
    assert 'export VITE_WEALL_LIVE_ROOM_EMBED="${LIVE_ROOM_EMBED}"' in script
    assert "live_room_embed=${LIVE_ROOM_EMBED}" in script
    assert "window.open(externalRoomUrl" in room
    assert "roomUrl && liveRoomEmbedEnabled() && showEmbeddedRoom" in room
    assert "Live room opened in a separate tab" in room


def test_vite_csp_names_local_or_self_hosted_frames_for_rehearsal_if_embed_opted_in() -> None:
    src = _read(WEB / "vite.config.ts")
    assert "frame-src 'self'" in src
    assert "http://127.0.0.1:*" in src
    assert "http://localhost:*" in src
    assert "https://meet.jit.si" not in src
