from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.session_keys import session_record_key


def _session_keys(raw_key: str) -> dict:
    return {session_record_key(raw_key): {"active": True, "ttl_s": 0}}


class DummyExecutor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self) -> dict:
        return self._state


def _state() -> dict:
    return {
        "chain_id": "test",
        "height": 1,
        "time": 1,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 1, "session_keys": _session_keys("sk-alice")},
            "@j1": {"nonce": 0, "poh_tier": 2, "session_keys": _session_keys("sk-j1")},
            "@j2": {"nonce": 0, "poh_tier": 2, "session_keys": _session_keys("sk-j2")},
            "@mallory": {"nonce": 0, "poh_tier": 2, "session_keys": _session_keys("sk-mallory")},
        },
        "poh": {
            "live_cases": {
                "case1": {
                    "account_id": "@alice",
                    "status": "init",
                    "session_commitment": "sc1",
                    "room_commitment": "room1",
                    "prompt_commitment": "prompt1",
                    "jurors": {
                        "@j1": {"role": "interacting", "accepted": True, "attended": False},
                        "@j2": {"role": "observing", "accepted": True, "attended": False},
                    },
                }
            },
            "live_sessions": {
                "session:case1": {
                    "case_id": "case1",
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


def test_live_room_presence_is_transport_only_and_ephemeral() -> None:
    c = _client()

    r = c.post(
        "/v1/poh/live/session/session:case1/presence",
        json={
            "account_id": "@j1",
            "status": "joined",
            "camera_enabled": True,
            "mic_enabled": False,
            "display_name": "Reviewer 1",
            "ts_ms": 123,
        },
        headers={"x-weall-account": "@j1", "x-weall-session-key": "sk-j1"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["authority"] == "transport_only_ephemeral"
    assert body["record"]["account_id"] == "@j1"
    assert body["record"]["role"] == "interacting"
    assert body["record"]["camera_enabled"] is True
    assert body["record"]["mic_enabled"] is False

    listed = c.get("/v1/poh/live/session/session:case1/presence")
    assert listed.status_code == 200, listed.text
    records = listed.json()["presence"]
    assert len(records) == 1
    assert records[0]["authority"] == "transport_only_ephemeral"

    # Presence is node-local helper state only; it must not mutate chain-derived participants.
    participants = c.get("/v1/poh/live/session/session:case1/participants")
    assert participants.status_code == 404


def test_live_room_presence_requires_case_participant() -> None:
    c = _client()
    r = c.post(
        "/v1/poh/live/session/session:case1/presence",
        json={"account_id": "@mallory", "status": "joined", "ts_ms": 123},
        headers={"x-weall-account": "@mallory", "x-weall-session-key": "sk-mallory"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["message"] == "live_room_participant_required"


def test_live_room_presence_requires_authenticated_account_header() -> None:
    c = _client()
    r = c.post(
        "/v1/poh/live/session/session:case1/presence",
        json={"account_id": "@j1", "status": "joined", "ts_ms": 123},
    )
    assert r.status_code == 403
    assert r.json()["error"]["message"] == "presence_account_header_required"


def test_live_room_presence_rejects_header_account_mismatch() -> None:
    c = _client()
    r = c.post(
        "/v1/poh/live/session/session:case1/presence",
        json={"account_id": "@j1", "status": "joined", "ts_ms": 123},
        headers={"x-weall-account": "@j2"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["message"] == "presence_account_header_mismatch"


def test_live_attendance_skeleton_binds_case_session_commitment_without_server_error() -> None:
    c = _client()

    r = c.post(
        "/v1/poh/live/tx/attendance",
        json={"case_id": "case1", "juror_id": "@j1", "attended": True},
    )

    assert r.status_code == 200, r.text
    tx = r.json()["tx"]
    assert tx["tx_type"] == "POH_LIVE_ATTENDANCE_MARK"
    assert tx["signer_hint"] == "@j1"
    assert tx["payload"]["case_id"] == "case1"
    assert tx["payload"]["juror_id"] == "@j1"
    assert tx["payload"]["attended"] is True
    assert tx["payload"]["session_commitment"] == "sc1"


def test_live_attendance_skeleton_uses_session_record_fallback_for_migrated_state() -> None:
    state = _state()
    del state["poh"]["live_cases"]["case1"]["session_commitment"]
    c = _client(state)

    r = c.post(
        "/v1/poh/live/tx/attendance",
        json={"case_id": "case1", "juror_id": "@j1", "attended": True},
    )

    assert r.status_code == 200, r.text
    assert r.json()["tx"]["payload"]["session_commitment"] == "sc1"


def test_live_attendance_skeleton_fails_closed_when_session_commitment_missing() -> None:
    state = _state()
    del state["poh"]["live_cases"]["case1"]["session_commitment"]
    del state["poh"]["live_sessions"]["session:case1"]["session_commitment"]
    c = _client(state)

    r = c.post(
        "/v1/poh/live/tx/attendance",
        json={"case_id": "case1", "juror_id": "@j1", "attended": True},
    )

    assert r.status_code == 400
    assert r.json()["error"]["code"] == "session_not_ready"


def test_live_verdict_skeleton_binds_case_session_commitment_without_server_error() -> None:
    c = _client()

    r = c.post(
        "/v1/poh/live/tx/verdict",
        json={"case_id": "case1", "verdict": "pass"},
    )

    assert r.status_code == 200, r.text
    tx = r.json()["tx"]
    assert tx["tx_type"] == "POH_LIVE_VERDICT_SUBMIT"
    assert tx["payload"]["case_id"] == "case1"
    assert tx["payload"]["verdict"] == "pass"
    assert tx["payload"]["session_commitment"] == "sc1"
