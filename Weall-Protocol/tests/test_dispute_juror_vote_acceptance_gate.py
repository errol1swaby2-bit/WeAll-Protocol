from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute
from weall.runtime.tx_admission import TxEnvelope


class _FakeExecutor:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _session(account: str) -> dict[str, Any]:
    key = f"{account.strip('@')}-session"
    return {"session_keys": {key: {"active": True, "issued_at_ts": 1_800_000_000, "ttl_s": 3600}}}


def _state(*, juror_status: str = "assigned", attendance: dict[str, Any] | None = None) -> dict[str, Any]:
    juror_record: dict[str, Any] = {"status": juror_status, "assigned_at_nonce": 1}
    if attendance is not None:
        juror_record["attendance"] = attendance
    return {
        "height": 10,
        "time": 1_800_000_000,
        "accounts": {
            "@juror": _session("@juror"),
            "@reporter": _session("@reporter"),
            "@owner": _session("@owner"),
        },
        "roles": {"validators": {"active_set": ["@juror"]}},
        "params": {
            "reputation": {
                "dispute": {
                    "juror_vote_window_blocks": 180,
                    "safe_withdraw_blocks": 45,
                    "late_withdraw_penalty_milli": 500,
                    "timeout_penalty_milli": 1500,
                }
            }
        },
        "content": {"posts": {"post-1": {"author": "@owner"}}},
        "disputes_by_id": {
            "disp-1": {
                "id": "disp-1",
                "stage": "juror_review",
                "opened_by": "@reporter",
                "reporter": "@reporter",
                "target_type": "content",
                "target_id": "post-1",
                "target_owner": "@owner",
                "eligible_juror_ids": ["@juror"],
                "assigned_jurors": ["@juror"],
                "jurors": {"@juror": juror_record},
                "votes": {},
            }
        },
    }


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any]) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="")


def test_dispute_vote_submit_cannot_implicitly_accept_assigned_juror_batch596() -> None:
    state = _state()

    try:
        apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@juror", 2, {"dispute_id": "disp-1", "vote": "yes"}))
    except DisputeApplyError as exc:
        assert exc.code == "forbidden"
        assert exc.reason == "juror_not_present"
        assert exc.details["requires"] == "DISPUTE_JUROR_ACCEPT"
    else:  # pragma: no cover - explicit failure branch for readability
        raise AssertionError("assigned juror vote must require explicit accept/attendance")

    juror = state["disputes_by_id"]["disp-1"]["jurors"]["@juror"]
    assert juror["status"] == "assigned"
    assert "accepted_at_nonce" not in juror
    assert state["disputes_by_id"]["disp-1"]["votes"] == {}


def test_dispute_vote_submit_after_accept_preserves_vote_and_reputation_batch596() -> None:
    state = _state()
    accept = apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "@juror", 2, {"dispute_id": "disp-1"})) or {}
    assert accept["applied"] == "DISPUTE_JUROR_ACCEPT"

    vote = apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@juror", 3, {"dispute_id": "disp-1", "vote": "yes"})) or {}
    assert vote["applied"] == "DISPUTE_VOTE_SUBMIT"
    dispute = state["disputes_by_id"]["disp-1"]
    assert dispute["jurors"]["@juror"]["status"] == "completed"
    assert dispute["votes"]["@juror"]["vote"] == "yes"
    codes = [str(ev.get("event_code")) for ev in state.get("reputation", {}).get("events", [])]
    assert "DISPUTE_JUROR_ACCEPTED" in codes
    assert "DISPUTE_JUROR_VOTED_ON_TIME" in codes


def test_dispute_vote_template_reports_acceptance_and_attendance_required_batch596(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_ALLOW_INSECURE_LOCALHOST", "1")
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(_state())
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/v1/disputes/disp-1/vote",
        headers={"x-weall-account": "@juror", "x-weall-session-key": "juror-session"},
        json={"vote": "yes"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["eligible"] is False
    assert body["requires_acceptance"] is True
    assert body["requires_attendance"] is True
    assert body["reasons"] == ["acceptance_required", "attendance_required"]
    assert body["tx_template"]["tx_type"] == "DISPUTE_VOTE_SUBMIT"


def test_dispute_vote_template_allows_accepted_present_juror_batch596(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_ALLOW_INSECURE_LOCALHOST", "1")
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(_state(juror_status="accepted", attendance={"present": True, "at_nonce": 2}))
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/v1/disputes/disp-1/vote",
        headers={"x-weall-account": "@juror", "x-weall-session-key": "juror-session"},
        json={"vote": "yes"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["eligible"] is True
    assert body["reasons"] == ["eligible"]
    assert body["requires_acceptance"] is False
    assert body["requires_attendance"] is False
