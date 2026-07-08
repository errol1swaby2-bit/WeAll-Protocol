from __future__ import annotations

from pathlib import Path
import time

from fastapi.testclient import TestClient

from weall.api.app import create_app


ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web"


class DummyExecutor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self) -> dict:
        return self._state


def _session(active: bool = True) -> dict:
    return {"active": active, "issued_at_ts": 1, "ttl_s": 100, "device_id": "browser:test"}


def _state() -> dict:
    return {
        "chain_id": "weall-batch409",
        "height": 7,
        "time": 10,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "session_keys": {"sk-alice": _session()}},
            "@j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "session_keys": {"sk-j1": _session()}},
            "@mallory": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "session_keys": {"sk-mallory": _session()}},
        },
        "poh": {
            "live_cases": {
                "live:alice:1": {
                    "account_id": "@alice",
                    "status": "init",
                    "session_commitment": "sc1",
                    "room_commitment": "room1",
                    "prompt_commitment": "prompt1",
                    "jurors": {"@j1": {"role": "interacting", "accepted": True}},
                }
            },
            "live_sessions": {
                "session:live:alice:1": {
                    "case_id": "live:alice:1",
                    "status": "active",
                    "session_commitment": "sc1",
                    "room_commitment": "room1",
                    "prompt_commitment": "prompt1",
                }
            },
            "live_session_participants": {},
        },
    }


def _client(state: dict | None = None) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = DummyExecutor(state or _state())
    return TestClient(app)


def _now_ms() -> int:
    return int(time.time() * 1000)


def test_webrtc_signal_bridge_import_is_operator_bound_and_visible_to_target(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN", "bridge-secret")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_ALLOWED_SOURCE_NODE_IDS", "observer")
    c = _client()
    session_id = "session:live:alice:1"

    no_token = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals/import",
        json={
            "source_node": "observer",
            "source_chain_id": "weall-controlled-devnet",
            "signal": {
                "signal_id": "webrtc:observer:1",
                "session_id": session_id,
                "from_account": "@alice",
                "to_account": "@j1",
                "type": "offer",
                "sdp": "v=0\no=- 1 1 IN IP4 127.0.0.1",
                "ts_ms": _now_ms(),
            },
        },
    )
    assert no_token.status_code == 403
    assert no_token.json()["error"]["message"] == "bad_webrtc_signal_bridge_token"

    imported = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals/import",
        headers={"x-weall-webrtc-signal-bridge-token": "bridge-secret"},
        json={
            "source_node": "observer",
            "source_chain_id": "weall-controlled-devnet",
            "signal": {
                "signal_id": "webrtc:observer:1",
                "session_id": session_id,
                "from_account": "@alice",
                "to_account": "@j1",
                "type": "offer",
                "sdp": "v=0\no=- 1 1 IN IP4 127.0.0.1",
                "ts_ms": _now_ms(),
            },
        },
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["imported"] is True
    assert imported.json()["signal"]["from_account"] == "@alice"

    listed = c.get(
        f"/v1/poh/live/session/{session_id}/webrtc/signals?since_seq=0",
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert listed.status_code == 200, listed.text
    assert [s["type"] for s in listed.json()["signals"]] == ["offer"]
    assert listed.json()["signals"][0]["to_account"] == "@j1"


def test_webrtc_signal_bridge_rejects_nonparticipant_and_untargeted_media(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN", "bridge-secret")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_ALLOWED_SOURCE_NODE_IDS", "observer")
    c = _client()
    session_id = "session:live:alice:1"
    headers = {"x-weall-webrtc-signal-bridge-token": "bridge-secret"}

    untargeted = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals/import",
        headers=headers,
        json={"source_node": "observer", "source_chain_id": "weall-controlled-devnet", "signal": {"signal_id": "webrtc:bad:1", "session_id": session_id, "from_account": "@alice", "type": "offer", "sdp": "v=0"}},
    )
    assert untargeted.status_code == 400
    assert untargeted.json()["error"]["message"] == "webrtc_target_required"

    nonparticipant = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals/import",
        headers=headers,
        json={"source_node": "observer", "source_chain_id": "weall-controlled-devnet", "signal": {"signal_id": "webrtc:bad:2", "session_id": session_id, "from_account": "@mallory", "to_account": "@j1", "type": "offer", "sdp": "v=0"}},
    )
    assert nonparticipant.status_code == 403
    assert nonparticipant.json()["error"]["message"] == "webrtc_source_must_be_case_participant"


def test_local_rehearsal_configures_two_way_webrtc_signal_bridge() -> None:
    src = (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")

    assert 'WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN="${SYNC_TOKEN}"' in src
    assert 'WEALL_WEBRTC_SIGNAL_PEER_URLS="${NODE2_API}"' in src
    assert 'WEALL_WEBRTC_SIGNAL_PEER_URLS="${NODE1_API}"' in src
    assert "webrtc_signal_bridge=enabled" in src


def test_reviewer_accepts_live_review_then_joins_and_checks_in_separately() -> None:
    src = (WEB / "src" / "pages" / "JurorDashboard.tsx").read_text(encoding="utf-8")

    assert "Accept live verification review" in src
    assert "Use Join call and check in as the separate attendance step" in src
    assert "joinLiveRoom(caseId);" not in src
    assert "Accept review" in src
    assert "Join call and check in" in src
