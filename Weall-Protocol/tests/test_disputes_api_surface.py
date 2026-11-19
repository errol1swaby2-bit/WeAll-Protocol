from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.disputes import router as disputes_router


class _Executor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self):
        return self._state


def _app_with_state(state: dict) -> FastAPI:
    app = FastAPI()
    app.state.executor = _Executor(state)
    app.include_router(disputes_router, prefix="/v1")
    return app


def test_disputes_api_surfaces_authoritative_dispute_list_and_detail() -> None:
    state = {
        "disputes_by_id": {
            "dispute:demo:1": {
                "id": "dispute:demo:1",
                "stage": "voting",
                "opened_by": "@alice",
                "opened_at_nonce": 9,
                "target_type": "content",
                "target_id": "post:1",
                "reason": "spam",
                "jurors": {
                    "@juror1": {"status": "accepted", "attendance": {"present": True}},
                    "@juror2": {"status": "assigned"},
                },
                "votes": {
                    "@juror1": {"vote": "yes", "at_nonce": 11},
                },
                "resolved": False,
                "resolution": None,
                "evidence": [],
                "appeals": [],
            }
        }
    }
    client = TestClient(_app_with_state(state))

    r = client.get("/v1/disputes")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["id"] == "dispute:demo:1"
    assert item["vote_counts"] == {"yes": 1, "no": 0, "abstain": 0}
    assert item["juror_counts"]["accepted"] == 1
    assert item["juror_counts"]["present"] == 1

    r2 = client.get("/v1/disputes/dispute:demo:1")
    assert r2.status_code == 200
    detail = r2.json()["dispute"]
    assert detail["id"] == "dispute:demo:1"
    assert detail["target_id"] == "post:1"

    r3 = client.get("/v1/disputes/dispute:demo:1/votes")
    assert r3.status_code == 200
    votes = r3.json()
    assert votes["ok"] is True
    assert votes["vote_counts"]["yes"] == 1


def test_pending_appeal_api_uses_safe_aggregate_and_not_review_queue() -> None:
    state = {
        "height": 101,
        "accounts": {"@subject": {"poh_tier": 2}},
        "disputes_by_id": {
            "d-pending": {
                "id": "d-pending",
                "stage": "appeal_pending_panel",
                "target_type": "account",
                "target_id": "@subject",
                "appeal_deadline_height": 80,
                "appeal_allowed_accounts": ["@subject"],
                "appeals": [
                    {
                        "by": "@subject",
                        "height": 25,
                        "at_nonce": 3,
                        "payload": {"reason": "Private appeal submission details"},
                    }
                ],
                "appeal_pending_since_height": 25,
                "appeal_panel_status": "insufficient_reviewer_pool",
                "appeal_panel_required_size": 7,
                "appeal_substitute_required_count": 2,
                "appeal_panel_available_candidate_count": 8,
                "jurors": {},
                "votes": {},
            }
        },
    }
    client = TestClient(_app_with_state(state))
    listing = client.get("/v1/disputes?active_only=true&include_summary=true")
    assert listing.status_code == 200
    item = listing.json()["items"][0]
    assert item["stage"] == "appeal_pending_panel"
    assert item["appeal_total"] == 1
    assert item["appeals_redacted"] is True
    assert "appeals" not in item
    assert "Private appeal submission details" not in str(item)
    readiness = item["appeal_panel_readiness"]
    assert readiness["pending"] is True
    assert readiness["enforcement_held"] is True
    assert readiness["required_panel_size"] == 7
    assert readiness["required_substitute_count"] == 2
    assert readiness["available_candidate_count"] == 8
    assert readiness["appeal_filed_at_height"] == 25
    assert readiness["next_action"] == "await_independent_jurors"
    assert listing.json()["summary"]["active"] == 1

    detail = client.get("/v1/disputes/d-pending").json()["dispute"]
    assert detail["appeal_total"] == 1
    assert detail["appeal_panel_readiness"] == readiness
