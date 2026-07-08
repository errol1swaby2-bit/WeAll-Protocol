from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.disputes import router as disputes_router
from weall.api.routes_public_parts.gov import router as gov_router
from weall.api.routes_public_parts.reputation import router as reputation_router
from weall.runtime.apply.content import apply_content
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.phase_progression import dispute_phase_status, governance_phase_status
from weall.runtime.reputation_accrual import schedule_reputation_accrual_system_txs
from weall.runtime.reputation_events import append_reputation_event
from weall.runtime.tx_admission_types import TxEnvelope


class _Executor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self):
        return self._state


def _app(state: dict) -> TestClient:
    app = FastAPI()
    app.state.executor = _Executor(state)
    app.include_router(gov_router, prefix="/v1")
    app.include_router(disputes_router, prefix="/v1")
    app.include_router(reputation_router, prefix="/v1")
    return TestClient(app)


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system)


def _gov_state() -> dict:
    return {
        "height": 10,
        "accounts": {
            "@alice": {"poh_tier": 2, "banned": False, "locked": False},
            "@bob": {"poh_tier": 2, "banned": False, "locked": False},
            "@carol": {"poh_tier": 2, "banned": False, "locked": False},
        },
    }


def test_governance_phase_status_advances_by_quorum_and_snapshot_does_not_grow_mid_phase() -> None:
    state = _gov_state()
    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {"proposal_id": "prop:quorum", "rules": {"start_stage": "voting", "vote_window_blocks": 20}, "title": "Q"},
        ),
    )
    proposal = state["gov_proposals_by_id"]["prop:quorum"]
    assert proposal["eligible_validator_count"] == 3
    assert proposal["required_votes"] == 2

    state["accounts"]["@dana"] = {"poh_tier": 2, "banned": False, "locked": False}
    apply_governance(state, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "prop:quorum", "vote": "yes"}))
    status = governance_phase_status(state, proposal, "prop:quorum")
    assert status["eligible_count"] == 3
    assert status["participation_count"] == 1
    assert status["transition_reason"] == "none"

    apply_governance(state, _env("GOV_VOTE_CAST", "@bob", 3, {"proposal_id": "prop:quorum", "vote": "yes"}))
    status = governance_phase_status(state, proposal, "prop:quorum")
    assert status["eligible_count"] == 3
    assert status["participation_count"] == 2
    assert status["quorum_reached"] is True
    assert status["transition_reason"] == "quorum"
    assert "small_network_quorum_route_not_public_beta_evidence" in status["blocking_reasons"]


def test_governance_next_phase_recomputes_denominator_after_userbase_growth() -> None:
    state = _gov_state()
    apply_governance(
        state,
        _env("GOV_PROPOSAL_CREATE", "@alice", 1, {"proposal_id": "prop:grow", "rules": {"start_stage": "poll"}}),
    )
    proposal = state["gov_proposals_by_id"]["prop:grow"]
    assert proposal["eligible_validator_count"] == 3
    state["height"] = 12
    state["accounts"]["@dana"] = {"poh_tier": 2, "banned": False, "locked": False}
    apply_governance(state, _env("GOV_STAGE_SET", "SYSTEM", 4, {"proposal_id": "prop:grow", "stage": "voting"}, system=True))
    assert proposal["eligible_validator_count"] == 4
    assert "@dana" in proposal["eligible_validator_ids"]
    status = governance_phase_status(state, proposal, "prop:grow")
    assert status["eligible_count"] == 4
    assert status["phase"] == "voting"


def _dispute_state() -> dict:
    return {
        "height": 20,
        "accounts": {
            "@reporter": {"poh_tier": 2},
            "@owner": {"poh_tier": 2},
            "@j1": {"poh_tier": 2},
            "@j2": {"poh_tier": 2},
            "@j3": {"poh_tier": 2},
        },
        "roles": {
            "jurors": {
                "active_set": ["@j1", "@j2", "@j3"],
                "by_id": {
                    "@j1": {"status": "active", "responsibilities": {"reviewer": {"dispute_review": {"opted_in": True, "active": True}}}},
                    "@j2": {"status": "active", "responsibilities": {"reviewer": {"dispute_review": {"opted_in": True, "active": True}}}},
                    "@j3": {"status": "active", "responsibilities": {"reviewer": {"dispute_review": {"opted_in": True, "active": True}}}},
                },
            }
        },
        "content": {"posts": {"post:1": {"author": "@owner", "body": "x"}}},
    }


def test_dispute_phase_status_uses_assigned_snapshot_and_does_not_shrink_mid_phase() -> None:
    state = _dispute_state()
    apply_dispute(state, _env("DISPUTE_OPEN", "@reporter", 1, {"dispute_id": "disp:1", "target_type": "content", "target_id": "post:1", "reason": "spam"}))
    dispute = state["disputes_by_id"]["disp:1"]
    assert dispute["eligible_validator_count"] == 3
    state["roles"]["jurors"]["by_id"]["@j3"]["status"] = "suspended"
    status = dispute_phase_status(state, dispute, "disp:1")
    assert status["eligible_count"] == 3
    assert status["quorum_required"] == 2

    dispute["votes"] = {"@j1": {"vote": "yes"}, "@j2": {"vote": "yes"}, "@j2-alias": {"vote": "yes"}}
    status = dispute_phase_status(state, dispute, "disp:1")
    assert status["participation_count"] == 2
    assert status["transition_reason"] == "quorum"


def test_dispute_phase_status_reports_block_height_and_quorum_tie_deterministically() -> None:
    state = _dispute_state()
    state["height"] = 50
    dispute = {
        "id": "disp:tie",
        "stage": "juror_review",
        "stage_set_at_height": 20,
        "deadline_height": 50,
        "eligible_juror_ids": ["@j1", "@j2", "@j3"],
        "required_votes": 2,
        "votes": {"@j1": {"vote": "yes"}, "@j2": {"vote": "no"}},
    }
    status = dispute_phase_status(state, dispute, "disp:tie")
    assert status["deadline_reached"] is True
    assert status["quorum_reached"] is True
    assert status["transition_reason"] == "block_height_and_quorum"


def test_reputation_content_accrual_caps_repeated_low_value_actions() -> None:
    state = {
        "height": 10,
        "params": {
            "content_reputation_maturity_blocks": 1,
            "post_reputation_delta_milli": 10,
            "content_reputation_window_blocks": 100,
            "content_reputation_max_delta_per_window_milli": 20,
        },
        "accounts": {"@new": {"poh_tier": 2, "reputation_milli": 0}},
    }
    for idx in range(3):
        apply_content(state, _env("CONTENT_POST_CREATE", "@new", idx + 1, {"post_id": f"post:{idx}", "body": f"clean {idx}", "visibility": "public"}))
    state["height"] = 12
    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 2
    queued = [item for item in state.get("system_queue", []) if item.get("tx_type") == "REPUTATION_DELTA_APPLY"]
    assert len(queued) == 2
    statuses = [state["content"]["posts"][f"post:{idx}"]["reputation_accrual"]["status"] for idx in range(3)]
    assert statuses.count("queued") == 2
    assert statuses.count("capped") == 1


def test_reputation_action_map_and_progression_status_api() -> None:
    state = {"height": 30, "accounts": {"@new": {"poh_tier": 2, "reputation_milli": 0}}}
    append_reputation_event(
        state,
        actor_id="@new",
        event_code="POH_TIER2_APPROVED",
        source_flow="poh",
        source_tx_id="tx:poh:1",
        source_object_id="poh:@new",
        occurred_at_block=30,
    )
    client = _app(state)
    action_map = client.get("/v1/reputation/action-map").json()
    assert action_map["ok"] is True
    assert action_map["action_count"] >= 60
    assert any(item["event_code"] == "POH_TIER2_APPROVED" for item in action_map["actions"])

    status = client.get("/v1/accounts/%40new/reputation-progression-status").json()
    assert status["ok"] is True
    assert status["account_id"] == "@new"
    assert "actions_available_without_spam" in status
    assert status["anti_farming_policy"].startswith("source-key dedupe")


def test_phase_status_api_surfaces_backend_quorum_truth() -> None:
    state = _gov_state()
    apply_governance(state, _env("GOV_PROPOSAL_CREATE", "@alice", 1, {"proposal_id": "prop:api", "rules": {"start_stage": "voting"}}))
    state.update(_dispute_state())
    apply_dispute(state, _env("DISPUTE_OPEN", "@reporter", 2, {"dispute_id": "disp:api", "target_type": "content", "target_id": "post:1", "reason": "spam"}))
    client = _app(state)
    gov = client.get("/v1/governance/prop:api/phase-status").json()
    assert gov["flow_type"] == "governance"
    assert gov["denominator_policy"] == "phase_open_snapshot_fixed_until_next_phase"
    dispute = client.get("/v1/disputes/disp:api/phase-status").json()
    assert dispute["flow_type"] == "dispute"
    assert dispute["online_user_quorum_forbidden"] is True
