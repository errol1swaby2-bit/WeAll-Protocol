from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.demo_seed import seed_demo_state
from weall.api.routes_public_parts.disputes import router as disputes_router
from weall.api.routes_public_parts.gov import router as gov_router
from weall.api.routes_public_parts.groups import router as groups_router


class _Executor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self):
        return self._state


def _mk_state() -> dict:
    return {
        "height": 0,
        "chain_id": "weall-dev",
        "accounts": {
            "@demo_tester": {
                "nonce": 5,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10,
                "keys": [],
            },
            "SYSTEM": {
                "nonce": 0,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10,
                "keys": [],
            },
        },
        "roles": {},
        "content": {
            "posts": {
                "post:@demo_tester:5": {
                    "post_id": "post:@demo_tester:5",
                    "author": "@demo_tester",
                    "body": "seed me",
                    "media": [],
                    "created_nonce": 5,
                    "visibility": "public",
                    "locked": False,
                    "tags": [],
                    "group_id": None,
                }
            }
        },
        "system_queue": [],
        "params": {"system_signer": "SYSTEM", "gov_action_allowlist": []},
    }


def _client_with_seeded_state() -> tuple[TestClient, dict]:
    state = _mk_state()
    seeded = seed_demo_state(state, account="@demo_tester", post_id="post:@demo_tester:5")

    app = FastAPI()
    app.state.executor = _Executor(state)
    app.include_router(groups_router, prefix="/v1")
    app.include_router(disputes_router, prefix="/v1")
    app.include_router(gov_router, prefix="/v1")
    return TestClient(app), seeded


def test_seeded_group_dispute_and_proposal_are_visible_through_public_routes() -> None:
    client, seeded = _client_with_seeded_state()
    group_id = seeded["group"]["group_id"]
    proposal_id = seeded["proposal"]["proposal_id"]
    dispute_id = seeded["dispute"]["dispute_id"]

    groups_res = client.get("/v1/groups")
    assert groups_res.status_code == 200, groups_res.text
    groups_body = groups_res.json()
    assert any(str(item.get("id") or "") == group_id for item in groups_body["items"])

    members_res = client.get(f"/v1/groups/{group_id}/members")
    assert members_res.status_code == 200, members_res.text
    members = members_res.json()["members"]
    assert any(str(item.get("account") or "") == "@demo_tester" for item in members)

    disputes_res = client.get("/v1/disputes")
    assert disputes_res.status_code == 200, disputes_res.text
    disputes_body = disputes_res.json()
    dispute_item = next(item for item in disputes_body["items"] if str(item.get("id") or "") == dispute_id)
    assert dispute_item["target_id"] == "post:@demo_tester:5"

    proposal_res = client.get("/v1/gov/proposals")
    assert proposal_res.status_code == 200, proposal_res.text
    proposal_body = proposal_res.json()
    proposal_item = next(item for item in proposal_body["items"] if str(item.get("proposal_id") or item.get("id") or "") == proposal_id)
    assert str(proposal_item.get("stage") or proposal_item.get("status") or "") == "voting"
    assert seeded["validator"]["active_validator_ids"] == ["@demo_tester"]

    proposal_detail = client.get(f"/v1/gov/proposals/{proposal_id}")
    assert proposal_detail.status_code == 200, proposal_detail.text
    assert proposal_detail.json()["proposal"]["proposal_id"] == proposal_id


def test_demo_seed_is_idempotent_for_seeded_demo_objects() -> None:
    state = _mk_state()
    first = seed_demo_state(state, account="@demo_tester", post_id="post:@demo_tester:5")
    second = seed_demo_state(state, account="@demo_tester", post_id="post:@demo_tester:5")

    assert first == second

    roles = state["roles"]
    groups = roles["groups_by_id"]
    jurors = roles["jurors"]
    proposals = state["gov_proposals_by_id"]
    disputes = state["disputes_by_id"]

    assert list(groups.keys()) == [first["group"]["group_id"]]
    assert list(proposals.keys()) == [first["proposal"]["proposal_id"]]
    assert list(disputes.keys()) == [first["dispute"]["dispute_id"]]
    assert jurors["active_set"] == ["@demo_tester"]
    assert roles["validators"]["active_set"] == ["@demo_tester"]
    assert "@demo_tester" in groups[first["group"]["group_id"]]["members"]
