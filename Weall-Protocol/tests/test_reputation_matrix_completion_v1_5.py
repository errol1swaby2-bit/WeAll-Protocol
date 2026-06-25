from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.reputation_events import (
    EVENT_REGISTRY,
    REPUTATION_DIMENSIONS,
    append_reputation_event,
    append_reputation_reversal_event,
    derive_role_eligibility,
    reduce_reputation_events,
    registry_payload,
    reputation_event_history_root,
)
from weall.runtime.reputation_matrix import derive_reputation_matrix
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


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


def _base_state(*, height: int = 10) -> dict[str, Any]:
    return {
        "height": height,
        "time": 1_800_000_000,
        "accounts": {
            "@juror": _session("@juror"),
            "@reporter": _session("@reporter"),
            "@owner": _session("@owner"),
            "@other": _session("@other"),
        },
        "roles": {"validators": {"active_set": ["@juror", "@other"]}},
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
                "eligible_juror_ids": ["@juror", "@other"],
                "assigned_jurors": ["@juror", "@other"],
                "jurors": {"@juror": {"status": "assigned", "assigned_at_nonce": 1}},
                "votes": {},
            }
        },
    }


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system)


def _accept(state: dict[str, Any], *, nonce: int = 2) -> dict[str, Any]:
    return apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "@juror", nonce, {"dispute_id": "disp-1"})) or {}


def _canonical_codes(state: dict[str, Any]) -> list[str]:
    return [str(ev.get("event_code")) for ev in state.get("reputation", {}).get("events", [])]


def test_reputation_registry_has_required_contract_fields() -> None:
    required = {
        "POH_TIER1_VERIFIED",
        "DISPUTE_JUROR_ACCEPTED",
        "DISPUTE_JUROR_WITHDREW_EARLY",
        "DISPUTE_JUROR_WITHDREW_LATE",
        "DISPUTE_JUROR_TIMED_OUT",
        "DISPUTE_JUROR_VOTED_ON_TIME",
        "GOVERNANCE_VOTED",
        "CONTENT_CONFIRMED_VIOLATION",
        "VALIDATOR_DOUBLE_SIGN",
        "STORAGE_FALSE_AVAILABILITY_CLAIM",
        "HELPER_REPLAY_ATTEMPT",
        "REPUTATION_EVENT_REVERSED",
    }
    assert required.issubset(EVENT_REGISTRY.keys())
    payload = registry_payload()
    assert payload["event_count"] >= 60
    for code, spec in EVENT_REGISTRY.items():
        assert spec.event_code == code
        assert spec.dimension in REPUTATION_DIMENSIONS
        assert isinstance(spec.default_delta, int)
        assert 0 <= spec.severity <= 5
        assert spec.decay_policy
        assert spec.eligibility_impact
        assert spec.explanation
        assert spec.visibility == "public"


def test_append_only_reputation_events_are_deduped_and_replayable() -> None:
    state: dict[str, Any] = {"height": 7, "time": 99}
    first = append_reputation_event(
        state,
        actor_id="@juror",
        event_code="DISPUTE_JUROR_TIMED_OUT",
        source_flow="dispute",
        source_tx_id="tx-1",
        source_object_id="disp-1:@juror",
        occurred_at_block=7,
        occurred_at_time=99,
    )
    duplicate = append_reputation_event(
        state,
        actor_id="@juror",
        event_code="DISPUTE_JUROR_TIMED_OUT",
        source_flow="dispute",
        source_tx_id="tx-1",
        source_object_id="disp-1:@juror",
        occurred_at_block=8,
        occurred_at_time=100,
    )
    assert first["event_id"] == duplicate["event_id"]
    assert duplicate["deduped"] is True
    events = state["reputation"]["events"]
    assert len(events) == 1
    reduced_a = reduce_reputation_events(events)
    reduced_b = reduce_reputation_events(list(reversed(events)))
    assert reduced_a == reduced_b
    assert reputation_event_history_root(events) == reputation_event_history_root(list(reversed(events)))
    dims = reduced_a["actors"]["@juror"]["dimensions"]
    assert dims["juror_reputation"]["score_milli"] < 0
    assert dims["poh_reputation"]["score_milli"] == 0


def test_appeal_reversal_adds_event_without_deleting_original() -> None:
    state: dict[str, Any] = {"height": 11, "time": 11}
    bad = append_reputation_event(
        state,
        actor_id="@creator",
        event_code="CONTENT_CONFIRMED_VIOLATION",
        source_flow="content",
        source_tx_id="tx-bad",
        source_object_id="post-1",
        occurred_at_block=11,
        occurred_at_time=11,
    )
    reversal = append_reputation_reversal_event(
        state,
        original_event_id=bad["event_id"],
        source_tx_id="appeal-tx-1",
        source_object_id="appeal-1",
        occurred_at_block=12,
        occurred_at_time=12,
        actor_id="@appeal-reviewer",
    )
    events = state["reputation"]["events"]
    assert [ev["event_code"] for ev in events] == ["CONTENT_CONFIRMED_VIOLATION", "REPUTATION_EVENT_REVERSED"]
    assert reversal["reversal_of_optional"] == bad["event_id"]
    reduced = reduce_reputation_events(events)
    dims = reduced["actors"]["@creator"]["dimensions"]
    assert dims["creator_reputation"]["score_milli"] == 0
    assert dims["appeal_correction_history"]["event_count"] == 1


def test_dispute_accept_creates_canonical_deadlines_and_accepted_event() -> None:
    state = _base_state(height=10)
    out = _accept(state)
    juror = state["disputes_by_id"]["disp-1"]["jurors"]["@juror"]
    assert out["vote_deadline_height"] == 190
    assert out["safe_withdraw_until_height"] == 55
    assert juror["accepted_at_height"] == 10
    assert "DISPUTE_JUROR_ACCEPTED" in _canonical_codes(state)
    assert state["reputation"]["events"][-1]["dimension"] == "juror_reputation"


def test_dispute_withdrawal_and_timeout_classifications_are_backend_canonical() -> None:
    early = _base_state(height=10)
    _accept(early)
    early["height"] = 20
    early_out = apply_dispute(early, _env("DISPUTE_JUROR_WITHDRAW", "@juror", 3, {"dispute_id": "disp-1"})) or {}
    assert early_out["safe"] is True
    assert early_out["delta_milli"] == 0
    assert "DISPUTE_JUROR_WITHDREW_EARLY" in _canonical_codes(early)

    late = _base_state(height=10)
    _accept(late)
    late["height"] = 70
    late_out = apply_dispute(late, _env("DISPUTE_JUROR_WITHDRAW", "@juror", 3, {"dispute_id": "disp-1"})) or {}
    assert late_out["safe"] is False
    assert late_out["delta_milli"] == -500
    assert "DISPUTE_JUROR_WITHDREW_LATE" in _canonical_codes(late)

    timed = _base_state(height=10)
    _accept(timed)
    timed["height"] = 191
    timeout_out = apply_dispute(timed, _env("DISPUTE_JUROR_TIMEOUT", "SYSTEM", 191, {"dispute_id": "disp-1", "juror": "@juror"}, system=True)) or {}
    assert timeout_out["delta_milli"] == -1500
    assert timed["disputes_by_id"]["disp-1"]["jurors"]["@juror"]["status"] == "timed_out"
    assert "DISPUTE_JUROR_TIMED_OUT" in _canonical_codes(timed)


def test_dispute_vote_before_deadline_completes_assignment_without_majority_penalty() -> None:
    state = _base_state(height=10)
    _accept(state)
    state["height"] = 20
    out = apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", "@juror", 4, {"dispute_id": "disp-1", "vote": "no"})) or {}
    assert out["applied"] == "DISPUTE_VOTE_SUBMIT"
    assert state["disputes_by_id"]["disp-1"]["jurors"]["@juror"]["status"] == "completed"
    assert "DISPUTE_JUROR_VOTED_ON_TIME" in _canonical_codes(state)
    matrix = derive_reputation_matrix(state, "@juror", reveal_private=True, include_events=True)
    assert matrix["visibility"]["private_dimensions"] == []
    assert matrix["visibility"]["private_revealed"] is False
    assert matrix["canonical_dimensions"]["juror_reputation"]["score_milli"] == 250
    assert not any("majority" in str(ev.get("reason_code", "")).lower() for ev in state["reputation"]["events"])


def test_role_eligibility_is_dimension_specific() -> None:
    state: dict[str, Any] = {"height": 1, "time": 1}
    append_reputation_event(
        state,
        actor_id="@validator",
        event_code="VALIDATOR_DOUBLE_SIGN",
        source_flow="validator",
        source_tx_id="slash-1",
        source_object_id="block-1",
        occurred_at_block=1,
        occurred_at_time=1,
    )
    eligibility = derive_role_eligibility(state, "@validator")
    assert eligibility["validator_operator"]["eligible"] is False
    assert eligibility["creator_trust"]["eligible"] is True
    assert eligibility["dispute_juror"]["eligible"] is True


def test_reputation_and_dispute_api_contracts_expose_backend_read_models(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_ALLOW_INSECURE_LOCALHOST", "1")
    state = _base_state(height=10)
    _accept(state)
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    client = TestClient(app, raise_server_exceptions=False)

    headers = {"x-weall-account": "@juror", "x-weall-session-key": "juror-session"}
    r = client.get("/v1/reputation/event-codes")
    assert r.status_code == 200
    assert r.json()["event_count"] == len(EVENT_REGISTRY)

    r = client.get("/v1/reputation/@juror/matrix", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["canonical_dimensions"]["juror_reputation"]["event_count"] >= 1
    assert "eligibility" in body

    r = client.get("/v1/reputation/@juror/eligibility")
    assert r.status_code == 200
    assert "dispute_juror" in r.json()["eligibility"]

    r = client.get("/v1/disputes/current", headers=headers)
    assert r.status_code == 200
    current = r.json()
    assert current["count"] == 1
    assert current["items"][0]["canonical_deadlines"]["vote_deadline_height"] == 190
    assert "1-hour review obligation" in current["items"][0]["reputation_warning"]["text"]

    r = client.get("/v1/disputes/eligible", headers={"x-weall-account": "@reporter", "x-weall-session-key": "reporter-session"})
    assert r.status_code == 200
    assert r.json()["count"] == 0

    r = client.post("/v1/disputes/disp-1/vote", headers=headers, json={"vote": "yes", "reason": "policy matched"})
    assert r.status_code == 200
    vote = r.json()
    assert vote["tx_template"]["tx_type"] == "DISPUTE_VOTE_SUBMIT"
    assert vote["deterministic_source"] == "signed_tx_submit"


def test_reputation_artifacts_are_generated() -> None:
    for name in (
        "reputation_event_registry_v1_5.json",
        "reputation_matrix_contract_v1_5.json",
        "reputation_flow_coverage_map_v1_5.json",
        "reputation_invariant_report_v1_5.json",
        "reputation_api_contract_map_v1_5.json",
    ):
        assert (ROOT / "generated" / name).exists()
