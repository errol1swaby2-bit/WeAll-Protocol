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
            "@alice": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "session_keys": {"sk-alice": _session()},
            },
            "@j1": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "session_keys": {"sk-j1": _session()},
            },
            "@mallory": {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "session_keys": {"sk-mallory": _session()},
            },
        },
        "poh": {
            "async_cases": {
                "async:alice:1": {
                    "account_id": "@alice",
                    "status": "assigned",
                    "assigned_jurors": ["@j1"],
                    "jurors": {"@j1": {"accepted": True}},
                    "evidence_commitments": {"ev1": {"evidence_commitment": "a" * 64}},
                    "evidence_binds": {
                        "ev1": {
                            "key_envelope_commitments": {
                                "@alice": {"envelope_commitment": "sha256:" + "1" * 64},
                                "@j1": {
                                    "algorithm": "ml-kem-768+aes-256-gcm",
                                    "kem_ciphertext_b64": "secret-kem-ciphertext",
                                    "wrapped_key_b64": "secret-wrapped-key",
                                    "context_commitment": "sha256:" + "5" * 64,
                                    "envelope_commitment": "sha256:" + "2" * 64,
                                },
                            }
                        }
                    },
                    "reviewer_restricted_evidence": {
                        "ev1": {
                            "encrypted": True,
                            "ciphertext_cid": "bafyciphertext",
                            "ciphertext_commitment": "sha256:" + "3" * 64,
                            "encryption_context_commitment": "sha256:" + "4" * 64,
                            "ciphertext_mime": "application/octet-stream",
                        }
                    },
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
    forged_case = forged.json()["case"]
    assert forged_case["reviewer_restricted_evidence"] == {}
    public_envelope = forged_case["evidence_binds"]["ev1"]["key_envelope_commitments"]["@j1"]
    assert public_envelope["envelope_commitment"].startswith("sha256:")
    assert "kem_ciphertext_b64" not in public_envelope
    assert "wrapped_key_b64" not in public_envelope

    authenticated = c.get(
        "/v1/poh/async/case/async:alice:1",
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert authenticated.status_code == 200, authenticated.text
    authenticated_case = authenticated.json()["case"]
    restricted = authenticated_case["reviewer_restricted_evidence"]["ev1"]
    assert restricted["encrypted"] is True
    assert restricted["ciphertext_cid"] == "bafyciphertext"
    assert "uri" not in restricted
    private_envelope = authenticated_case["evidence_binds"]["ev1"]["key_envelope_commitments"][
        "@j1"
    ]
    assert private_envelope["kem_ciphertext_b64"] == "secret-kem-ciphertext"
    assert private_envelope["wrapped_key_b64"] == "secret-wrapped-key"

    closed_state = _state()
    closed_case = closed_state["poh"]["async_cases"]["async:alice:1"]
    closed_case["status"] = "approved"
    closed_case["outcome"] = "approved"
    closed = _client(closed_state).get(
        "/v1/poh/async/case/async:alice:1",
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert closed.status_code == 200, closed.text
    closed_case_view = closed.json()["case"]
    assert closed_case_view["reviewer_restricted_evidence"] == {}
    closed_envelope = closed_case_view["evidence_binds"]["ev1"]["key_envelope_commitments"]["@j1"]
    assert "kem_ciphertext_b64" not in closed_envelope
    assert "wrapped_key_b64" not in closed_envelope


def test_restricted_async_case_joins_case_scoped_lifecycle_envelopes(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    state = _state()
    case = state["poh"]["async_cases"]["async:alice:1"]
    case["evidence_binds"] = {
        "bind:ev1": {
            "evidence_id": "ev1",
            "evidence_bind_commitment": "sha256:" + "6" * 64,
        }
    }
    state["poh"]["evidence_lifecycle"] = {
        "by_evidence": {
            "ev1": {
                "case_id": "async:alice:1",
                "evidence_id": "ev1",
                "state": "reviewer_accessible",
                "key_envelope_commitments": {
                    "@alice": {
                        "algorithm": "ml-kem-768+aes-256-gcm",
                        "context_commitment": "sha256:" + "7" * 64,
                        "envelope_commitment": "sha256:" + "8" * 64,
                        "kem_ciphertext_b64": "alice-private-kem",
                        "wrapped_key_b64": "alice-private-wrapped",
                    },
                    "@j1": {
                        "algorithm": "ml-kem-768+aes-256-gcm",
                        "context_commitment": "sha256:" + "9" * 64,
                        "envelope_commitment": "sha256:" + "a" * 64,
                        "kem_ciphertext_b64": "reviewer-private-kem",
                        "wrapped_key_b64": "reviewer-private-wrapped",
                    },
                },
            }
        }
    }
    client = _client(state)

    public = client.get("/v1/poh/async/case/async:alice:1")
    assert public.status_code == 200, public.text
    public_bind = public.json()["case"]["evidence_binds"]["bind:ev1"]
    assert public_bind["evidence_id"] == "ev1"
    assert "kem_ciphertext_b64" not in public_bind.get("key_envelope_commitments", {}).get(
        "@j1", {}
    )
    assert "wrapped_key_b64" not in public_bind.get("key_envelope_commitments", {}).get("@j1", {})

    reviewer = client.get(
        "/v1/poh/async/case/async:alice:1",
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert reviewer.status_code == 200, reviewer.text
    reviewer_bind = reviewer.json()["case"]["evidence_binds"]["bind:ev1"]
    assert (
        reviewer_bind["key_envelope_commitments"]["@j1"]["kem_ciphertext_b64"]
        == "reviewer-private-kem"
    )
    assert (
        reviewer_bind["key_envelope_commitments"]["@j1"]["wrapped_key_b64"]
        == "reviewer-private-wrapped"
    )

    subject = client.get(
        "/v1/poh/async/my-cases?account=@alice",
        headers={"x-weall-account": "@alice", "x-weall-session-key": "sk-alice"},
    )
    assert subject.status_code == 200, subject.text
    subject_bind = subject.json()["cases"][0]["evidence_binds"]["bind:ev1"]
    assert (
        subject_bind["key_envelope_commitments"]["@alice"]["kem_ciphertext_b64"]
        == "alice-private-kem"
    )

    closed_state = _state()
    closed_case = closed_state["poh"]["async_cases"]["async:alice:1"]
    closed_case["status"] = "approved"
    closed_case["outcome"] = "approved"
    closed_case["evidence_binds"] = case["evidence_binds"]
    closed_state["poh"]["evidence_lifecycle"] = state["poh"]["evidence_lifecycle"]
    closed = _client(closed_state).get(
        "/v1/poh/async/case/async:alice:1",
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert closed.status_code == 200, closed.text
    closed_bind = closed.json()["case"]["evidence_binds"]["bind:ev1"]
    assert "kem_ciphertext_b64" not in closed_bind.get("key_envelope_commitments", {}).get(
        "@j1", {}
    )
    assert "wrapped_key_b64" not in closed_bind.get("key_envelope_commitments", {}).get("@j1", {})


def test_async_case_read_and_review_skeleton_preserve_followup_round(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    state = _state()
    case = state["poh"]["async_cases"]["async:alice:1"]
    case["status"] = "needs_followup"
    case["followup_round"] = 1
    client = _client(state)

    read = client.get("/v1/poh/async/case/async:alice:1")
    assert read.status_code == 200, read.text
    assert read.json()["case"]["followup_round"] == 1

    skeleton = client.post(
        "/v1/poh/async/tx/review",
        json={
            "case_id": "async:alice:1",
            "verdict": "approve",
            "reason_code": "reviewed_followup",
            "followup_round": 1,
        },
    )
    assert skeleton.status_code == 200, skeleton.text
    payload = skeleton.json()["tx"]["payload"]
    assert payload["followup_round"] == 1
    assert payload["reason_code"] == "reviewed_followup"


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
    assert (
        missing_session.json()["error"]["message"]
        == "authenticated session required for WebRTC live-room signaling"
    )

    sent = c.post(
        f"/v1/poh/live/session/{session_id}/webrtc/signals",
        headers={"x-weall-account": "@alice", "x-weall-session-key": "sk-alice"},
        json={
            "account_id": "@alice",
            "type": "offer",
            "to_account": "@j1",
            "sdp": "v=0\no=- 1 1 IN IP4 127.0.0.1",
            "ts_ms": 2,
        },
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
        json={
            "account_id": "@alice",
            "type": "ice",
            "to_account": "@j1",
            "candidate": {"candidate": "x" * (9 * 1024)},
        },
    )
    assert bad_candidate.status_code == 400
    assert bad_candidate.json()["error"]["message"] == "webrtc_candidate_too_large"


def test_cors_allows_encrypted_poh_upload_commitment_headers(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_CORS_ORIGINS", "http://127.0.0.1:5173")
    client = _client()
    requested_headers = [
        "x-weall-account",
        "x-weall-session-key",
        "x-weall-evidence-encryption",
        "x-weall-evidence-context-commitment",
        "x-weall-evidence-ciphertext-commitment",
    ]
    response = client.options(
        "/v1/poh/async/evidence/video/upload",
        headers={
            "origin": "http://127.0.0.1:5173",
            "access-control-request-method": "POST",
            "access-control-request-headers": ",".join(requested_headers),
        },
    )
    assert response.status_code == 200, response.text
    allowed = str(response.headers.get("access-control-allow-headers") or "").lower()
    for header in requested_headers:
        assert header in allowed


def test_frontend_uses_real_webrtc_primitives_and_signaling() -> None:
    live_room = (
        Path(__file__).resolve().parents[2] / "web" / "src" / "pages" / "LiveVerificationRoom.tsx"
    ).read_text(encoding="utf-8")
    webrtc = (
        Path(__file__).resolve().parents[2] / "web" / "src" / "lib" / "webrtcLiveRoom.ts"
    ).read_text(encoding="utf-8")
    api = (Path(__file__).resolve().parents[2] / "web" / "src" / "api" / "weall.ts").read_text(
        encoding="utf-8"
    )

    assert "new RTCPeerConnection" in webrtc
    assert "navigator.mediaDevices.getUserMedia" in webrtc
    assert "createOffer" in live_room
    assert "setRemoteDescription" in live_room
    assert "addIceCandidate" in live_room
    assert "pohLiveWebRTCSignalSend" in api
    assert "/webrtc/signals" in api


def test_encrypted_poh_upload_binds_exact_bytes_and_controlled_store_is_retrievable(
    monkeypatch, tmp_path
) -> None:
    import hashlib

    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD", "1")
    monkeypatch.setenv("WEALL_POH_ENCRYPTED_LOCAL_STORE_ENABLED", "1")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "media-cache"))
    monkeypatch.setenv("WEALL_EVIDENCE_PROVIDER_ID", "@j1")
    monkeypatch.setenv("WEALL_MEDIA_PROXY_FETCH_ENABLED", "0")
    client = _client()
    ciphertext = b"WEALL_POH_EVIDENCE_V1\0" + (b"x" * 96)
    commitment = "sha256:" + hashlib.sha256(ciphertext).hexdigest()
    headers = {
        "x-weall-account": "@alice",
        "x-weall-session-key": "sk-alice",
        "x-weall-evidence-encryption": "aes-256-gcm",
        "x-weall-evidence-context-commitment": "sha256:" + "4" * 64,
        "x-weall-evidence-ciphertext-commitment": commitment,
    }

    mismatch = client.post(
        "/v1/poh/async/evidence/video/upload",
        headers={**headers, "x-weall-evidence-ciphertext-commitment": "sha256:" + "0" * 64},
        files={"file": ("evidence.weall-evidence", ciphertext, "application/octet-stream")},
    )
    assert mismatch.status_code == 400, mismatch.text
    assert mismatch.json()["error"]["message"] == "ciphertext_commitment_mismatch"

    uploaded = client.post(
        "/v1/poh/async/evidence/video/upload",
        headers=headers,
        files={"file": ("evidence.weall-evidence", ciphertext, "application/octet-stream")},
    )
    assert uploaded.status_code == 200, uploaded.text
    body = uploaded.json()
    assert body["provider_id"] == "@j1"
    assert body["video_commitment"] == commitment
    assert body["gateway_url"].startswith("/v1/media/proxy/")

    fetched = client.get(f"/v1/media/proxy/{body['cid']}")
    assert fetched.status_code == 200, fetched.text
    assert fetched.content == ciphertext
