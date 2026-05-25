from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"


def test_live_room_csp_names_local_or_self_hosted_sources_batch393() -> None:
    src = (WEB / "vite.config.ts").read_text(encoding="utf-8")

    assert "frame-src 'self' http://127.0.0.1:* http://localhost:*;" in src
    assert "frame-src 'self' http://127.0.0.1:* http://localhost:* https:;" not in src
    assert "https://meet.jit.si" not in src
    assert "https://*.jit.si" not in src
