from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.reputation import router as reputation_router
from weall.runtime.reputation_matrix import derive_reputation_matrix


class _Executor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self):
        return self._state


def _app_with_state(state: dict) -> FastAPI:
    app = FastAPI()
    app.state.executor = _Executor(state)
    app.include_router(reputation_router, prefix="/v1")
    return app


def _state() -> dict:
    return {
        "height": 100,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation_milli": 1250,
                "reputation": 1.25,
            },
            "@bob": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation_milli": 0,
                "reputation": 0,
            },
        },
        "reputation": {
            "deltas": [
                {
                    "delta_id": "repaccrual:post:post:1",
                    "account_id": "@alice",
                    "delta": 0.25,
                    "delta_milli": 250,
                    "reason": "content_post_matured",
                    "at_nonce": 10,
                    "payload": {"source": "content"},
                },
                {
                    "delta_id": "slash:eq:@alice:1",
                    "account_id": "@alice",
                    "delta": -25.0,
                    "delta_milli": -25000,
                    "reason": "equivocation",
                    "at_nonce": 11,
                    "payload": {"source": "consensus", "slash_id": "slash:1"},
                },
            ],
            "threshold_crossings": [],
        },
        "disputes_by_id": {
            "dispute:1": {
                "id": "dispute:1",
                "stage": "finalized",
                "assigned_jurors": {"@alice": {"status": "accepted"}},
                "votes": {"@alice": {"vote": "yes", "at_nonce": 20}},
            }
        },
        "gov_proposals_by_id": {
            "gov:1": {
                "proposal_id": "gov:1",
                "creator": "@alice",
                "stage": "voting",
                "votes": {"@alice": {"vote": "yes"}},
                "comments": [{"comment_id": "c1", "by": "@alice", "body": "support"}],
            }
        },
        "poh": {
            "async_cases": {
                "poh:1": {
                    "case_id": "poh:1",
                    "account_id": "@alice",
                    "status": "verified",
                    "reviews": {"@alice": {"vote": "approve"}},
                }
            }
        },
        "roles": {
            "validators": {"active_set": ["@alice"]},
            "node_operators": {
                "by_id": {
                    "@alice": {
                        "responsibilities": {
                            "storage": {
                                "active": True,
                                "proof_status": "verified",
                                "availability_score_milli": 900,
                            }
                        }
                    }
                }
            },
        },
        "validators": {"registry": {"@alice": {"status": "active"}}},
        "slashing": {
            "executions": {
                "slash:1": {"validator": "@alice", "type": "equivocation"}
            }
        },
        "content": {
            "posts": {
                "post:1": {
                    "post_id": "post:1",
                    "author": "@alice",
                    "visibility": "public",
                    "deleted": False,
                }
            },
            "comments": {
                "comment:1": {"comment_id": "comment:1", "author": "@alice", "post_id": "post:1"}
            },
        },
        "meta": {
            "helper_reputation": {
                "@alice": {"score": 3, "success": 4, "timeout": 1, "fraud": 0}
            }
        },
    }


def test_reputation_matrix_derives_all_public_dimensions_and_private_boundary() -> None:
    matrix = derive_reputation_matrix(_state(), "@alice", reveal_private=False, include_events=True)

    assert matrix["ok"] is True
    assert matrix["version"] == 1
    assert matrix["deterministic"] is True
    assert matrix["formula"]["integer_milli_units"] is True
    assert matrix["formula"]["wall_clock_time"] is False
    assert "abuse_risk" not in matrix["dimensions"]
    assert matrix["visibility"]["private_revealed"] is False

    dims = matrix["dimensions"]
    for name in (
        "juror",
        "dispute_participation",
        "validator",
        "helper",
        "storage",
        "creator",
        "governance",
        "identity_poh",
        "social_trust",
    ):
        assert name in dims
        assert isinstance(dims[name]["score_milli"], int)

    event_types = {event["event_type"] for event in matrix["events"]}
    assert "DISPUTE_VOTE_COMPLETED" in event_types
    assert "GOV_PROPOSAL_CREATED" in event_types
    assert "POH_TIER_ATTAINED" in event_types
    assert "VALIDATOR_STATUS_RECORDED" in event_types
    assert "STORAGE_RESPONSIBILITY_RECORDED" in event_types
    assert "HELPER_REPUTATION_RECORDED" in event_types
    assert "CONTENT_POST_PRESENT" in event_types


def test_reputation_matrix_owner_mode_includes_private_abuse_risk() -> None:
    matrix = derive_reputation_matrix(_state(), "@alice", reveal_private=True, include_events=True)

    assert "abuse_risk" in matrix["dimensions"]
    assert matrix["visibility"]["private_revealed"] is True
    assert any(event["dimension"] == "abuse_risk" for event in matrix["events"])


def test_reputation_matrix_api_summary_and_events_are_public_redacted() -> None:
    client = TestClient(_app_with_state(_state()))

    summary = client.get("/v1/reputation/%40alice/summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["ok"] is True
    assert body["account_id"] == "@alice"
    assert "abuse_risk" not in body["dimensions"]
    assert body["event_count"] >= 0

    events = client.get("/v1/reputation/%40alice/events")
    assert events.status_code == 200
    event_body = events.json()
    assert event_body["ok"] is True
    assert event_body["account_id"] == "@alice"
    assert all(event["visibility"] == "public" for event in event_body["events"])
