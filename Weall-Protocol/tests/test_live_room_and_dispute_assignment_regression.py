from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NESTED = ROOT / "Weall-Protocol"
WEB = ROOT / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_local_rehearsal_provides_live_room_transport_config_batch391() -> None:
    src = _read(NESTED / "scripts" / "devnet_local_two_frontend_rehearsal.sh")
    assert 'LIVE_ROOM_TRANSPORT_MODE="${VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE:-p2p}"' in src
    assert 'LIVE_ROOM_BASE_URL="${VITE_WEALL_LIVE_ROOM_BASE_URL:-}"' in src
    assert src.count('export VITE_WEALL_LIVE_ROOM_BASE_URL="${LIVE_ROOM_BASE_URL}"') >= 2
    assert 'live_room_transport=${LIVE_ROOM_TRANSPORT_MODE}' in src
    assert 'live_room_base_url=${LIVE_ROOM_BASE_URL}' in src


def test_vite_dev_csp_allows_local_p2p_room_frames_batch391() -> None:
    src = _read(WEB / "vite.config.ts")
    assert "frame-src 'self'" in src
    assert "http://127.0.0.1:*" in src
    assert "http://localhost:*" in src
    assert "https://meet.jit.si" not in src


def test_dispute_viewer_assignment_falls_back_to_eligible_juror_ids_batch391() -> None:
    api = _read(NESTED / "src" / "weall" / "api" / "routes_public_parts" / "disputes.py")
    surface = _read(WEB / "src" / "lib" / "disputeSurface.ts")
    apply = _read(NESTED / "src" / "weall" / "runtime" / "apply" / "dispute.py")

    assert 'eligible = obj.get("eligible_juror_ids")' in api
    assert '"source": "eligible_juror_ids"' in api
    assert 'function listContainsAccount' in surface
    assert 'src.eligible_juror_ids' in surface
    assert 'function disputeJurorRecord' in surface
    assert 'def _eligible_key_for_actor' in apply
    assert 'jurors[juror_key] = {"status": "assigned"' in apply
