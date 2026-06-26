from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app


class DummyExecutor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self) -> dict:
        return self._state


def _session(active: bool = True) -> dict:
    return {"active": active, "issued_at_ts": 1, "ttl_s": 100, "device_id": "browser:test"}


def _state() -> dict:
    return {
        "chain_id": "weall-batch407",
        "height": 7,
        "time": 10,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "session_keys": {"sk-alice": _session()}},
            "@j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "session_keys": {"sk-j1": _session()}},
            "@mallory": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "session_keys": {"sk-mallory": _session()}},
        },
        "poh": {
            "async_cases": {
                "async:alice:1": {
                    "account_id": "@alice",
                    "status": "assigned",
                    "assigned_jurors": ["@j1"],
                    "jurors": {"@j1": {"accepted": True}},
                    "evidence_commitments": {"ev1": {"evidence_commitment": "a" * 64}},
                    "reviewer_restricted_evidence": {"ev1": {"uri": "ipfs://bafyprivate", "mime": "video/webm"}},
                    "reviewable_evidence": {},
                    "public_evidence_ids": [],
                }
            },
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


def test_private_async_evidence_requires_authenticated_session_in_prod(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    c = _client()

    forged = c.get(
        "/v1/poh/async/case/async:alice:1",
        headers={"x-weall-account": "@j1"},
    )
    assert forged.status_code == 200, forged.text
    assert forged.json()["case"]["reviewer_restricted_evidence"] == {}

    authenticated = c.get(
        "/v1/poh/async/case/async:alice:1",
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert authenticated.status_code == 200, authenticated.text
    assert authenticated.json()["case"]["reviewer_restricted_evidence"]["ev1"]["uri"] == "ipfs://bafyprivate"


def test_webrtc_signaling_is_session_bound_case_scoped_and_ephemeral(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    c = _client()
    session_id = "session:live:alice:1"

    missing_session = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals",
        headers={"x-weall-account": "@alice"},
        json={"account_id": "@alice", "type": "hello", "ts_ms": 1},
    )
    assert missing_session.status_code == 403
    assert missing_session.json()["error"]["message"] == "authenticated session required for WebRTC live-room signaling"

    sent = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals",
        headers={"x-weall-account": "@alice", "x-weall-session-key": "sk-alice"},
        json={"account_id": "@alice", "type": "offer", "to_account": "@j1", "sdp": "v=0\no=- 1 1 IN IP4 127.0.0.1", "ts_ms": 2},
    )
    assert sent.status_code == 200, sent.text
    body = sent.json()
    assert body["authority"] == "transport_only_ephemeral"
    assert body["signal"]["type"] == "offer"
    assert body["signal"]["from_account"] == "@alice"

    listed = c.get(
        f"/v1/poh/live/session/{session_id}/webrtc/signals?since_seq=0",
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert listed.status_code == 200, listed.text
    signals = listed.json()["signals"]
    assert len(signals) == 1
    assert signals[0]["to_account"] == "@j1"

    mallory = c.get(
        f"/v1/poh/live/session/{session_id}/webrtc/signals?since_seq=0",
        headers={"x-weall-account": "@mallory", "x-weall-session-key": "sk-mallory"},
    )
    assert mallory.status_code == 403
    assert mallory.json()["error"]["message"] == "live_room_participant_required"


def test_webrtc_signal_rejects_nonparticipant_target_and_oversized_candidate(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    c = _client()
    session_id = "session:live:alice:1"

    bad_target = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals",
        headers={"x-weall-account": "@alice", "x-weall-session-key": "sk-alice"},
        json={"account_id": "@alice", "type": "offer", "to_account": "@mallory", "sdp": "v=0"},
    )
    assert bad_target.status_code == 403
    assert bad_target.json()["error"]["message"] == "webrtc_target_must_be_case_participant"

    bad_candidate = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals",
        headers={"x-weall-account": "@alice", "x-weall-session-key": "sk-alice"},
        json={"account_id": "@alice", "type": "ice", "to_account": "@j1", "candidate": {"candidate": "x" * (9 * 1024)}},
    )
    assert bad_candidate.status_code == 400
    assert bad_candidate.json()["error"]["message"] == "webrtc_candidate_too_large"


def test_frontend_uses_real_webrtc_primitives_and_signaling() -> None:
    live_room = (Path(__file__).resolve().parents[2] / "web" / "src" / "pages" / "LiveVerificationRoom.tsx").read_text(encoding="utf-8")
    webrtc = (Path(__file__).resolve().parents[2] / "web" / "src" / "lib" / "webrtcLiveRoom.ts").read_text(encoding="utf-8")
    api = (Path(__file__).resolve().parents[2] / "web" / "src" / "api" / "weall.ts").read_text(encoding="utf-8")

    assert "new RTCPeerConnection" in webrtc
    assert "navigator.mediaDevices.getUserMedia" in webrtc
    assert "createOffer" in live_room
    assert "setRemoteDescription" in live_room
    assert "addIceCandidate" in live_room
    assert "pohLiveWebRTCSignalSend" in api
    assert "/webrtc/signals" in api
