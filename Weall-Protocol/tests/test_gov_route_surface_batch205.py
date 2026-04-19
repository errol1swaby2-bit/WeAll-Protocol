from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.gov import router as gov_router


class _Executor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self):
        return self._state


def _app_with_state(state: dict) -> FastAPI:
    app = FastAPI()
    app.state.executor = _Executor(state)
    app.include_router(gov_router, prefix="/v1")
    return app


def _seed_state() -> dict:
    return {
        "gov_proposals_by_id": {
            "p-poll": {
                "proposal_id": "p-poll",
                "title": "Poll",
                "stage": "poll",
                "creator": "alice",
                "poll_votes": {"@a": {"vote": "yes"}},
            },
            "p-vote": {
                "proposal_id": "p-vote",
                "title": "Vote",
                "stage": "voting",
                "creator": "alice",
                "votes": {"@a": {"vote": "no"}},
            },
            "p-final": {
                "proposal_id": "p-final",
                "title": "Final",
                "stage": "finalized",
                "creator": "alice",
                "votes": {"@a": {"vote": "yes"}, "@b": {"vote": "abstain"}},
            },
            "p-withdrawn": {
                "proposal_id": "p-withdrawn",
                "title": "Withdrawn",
                "stage": "withdrawn",
                "creator": "alice",
            },
        }
    }


def test_gov_proposals_active_only_and_summary_batch205() -> None:
    client = TestClient(_app_with_state(_seed_state()))

    res = client.get("/v1/gov/proposals", params={"active_only": 1, "include_summary": 1, "limit": 50})
    assert res.status_code == 200
    body = res.json()

    ids = [str(item.get("proposal_id") or item.get("id") or "") for item in body["items"]]
    assert ids == ["p-vote", "p-poll"]
    assert body["summary"] == {
        "total": 4,
        "active": 2,
        "by_stage": {"finalized": 1, "poll": 1, "voting": 1, "withdrawn": 1},
    }
    assert body["items"][0]["is_active"] is True
    assert body["items"][0]["counts_current"] == {"yes": 0, "no": 1, "abstain": 0}
    assert body["items"][1]["counts_current"] == {"yes": 1, "no": 0, "abstain": 0}


def test_gov_proposals_stage_filter_batch205() -> None:
    client = TestClient(_app_with_state(_seed_state()))

    res = client.get("/v1/gov/proposals", params={"stage": "finalized", "limit": 50})
    assert res.status_code == 200
    body = res.json()
    assert len(body["items"]) == 1
    proposal = body["items"][0]
    assert proposal["proposal_id"] == "p-final"
    assert proposal["counts_current"] == {"yes": 1, "no": 0, "abstain": 1}
    assert proposal["vote_window"] == "final"
