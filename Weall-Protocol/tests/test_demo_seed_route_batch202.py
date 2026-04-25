from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.demo_seed import _LedgerStoreWriter, router, seed_demo_state


class _Executor:
    def __init__(self, state: dict):
        self.state = state
        self._ledger_store = _LedgerStoreWriter()

    def read_state(self):
        return self.state


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


def test_seed_demo_state_creates_group_proposal_and_juror_ready_dispute() -> None:
    state = _mk_state()

    result = seed_demo_state(state, account="@demo_tester", post_id="post:@demo_tester:5")

    assert result["validator"]["active_validator_ids"] == ["@demo_tester"]
    assert result["validator"]["eligible_validator_count"] == 1
    assert result["validator"]["required_votes"] == 1
    assert result["group"]["group_id"] == "g:demo-tester:demo-public"
    assert result["group"]["member_visible"] is True
    assert result["proposal"]["proposal_id"] == "proposal:demo-tester:demo-vote"
    assert result["proposal"]["stage"] == "voting"
    assert result["dispute"]["dispute_id"] == "dispute:demo-tester:demo-post"
    assert result["dispute"]["juror"] == "@demo_tester"
    assert result["dispute"]["juror_status"] == "assigned"
    assert result["dispute"]["stage"] == "juror_review"

    jurors = state["roles"]["jurors"]
    assert "@demo_tester" in jurors["by_id"]
    assert "@demo_tester" in jurors["active_set"]
    assert state["roles"]["validators"]["active_set"] == ["@demo_tester"]
    assert state["consensus"]["validator_set"]["active_set"] == ["@demo_tester"]


def test_demo_seed_route_persists_seeded_state_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_ENABLE_DEMO_SEED_ROUTE", "1")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "seeded_demo")
    monkeypatch.setenv("WEALL_MODE", "dev")
    app = FastAPI()
    ex = _Executor(_mk_state())
    app.state.executor = ex
    app.include_router(router, prefix="/v1")
    client = TestClient(app)

    res = client.post("/v1/dev/demo-seed", json={"account": "@demo_tester", "post_id": "post:@demo_tester:5"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["validator"]["required_votes"] == 1
    assert body["group"]["member_visible"] is True
    assert body["proposal"]["stage"] == "voting"
    assert body["dispute"]["juror_status"] == "assigned"
    assert ex._ledger_store.last_written is ex.state


def test_demo_seed_route_hidden_when_disabled(monkeypatch) -> None:
    monkeypatch.delenv("WEALL_ENABLE_DEMO_SEED_ROUTE", raising=False)
    app = FastAPI()
    app.state.executor = _Executor(_mk_state())
    app.include_router(router, prefix="/v1")
    client = TestClient(app, raise_server_exceptions=False)
    res = client.post("/v1/dev/demo-seed", json={"account": "@demo_tester", "post_id": "post:@demo_tester:5"})
    assert res.status_code == 404


def test_demo_seed_route_hidden_when_env_enabled_without_seeded_demo_profile(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_ENABLE_DEMO_SEED_ROUTE", "1")
    monkeypatch.setenv("WEALL_RUNTIME_PROFILE", "multi_node_devnet")
    monkeypatch.setenv("WEALL_MODE", "dev")
    app = FastAPI()
    app.state.executor = _Executor(_mk_state())
    app.include_router(router, prefix="/v1")
    client = TestClient(app, raise_server_exceptions=False)
    res = client.post("/v1/dev/demo-seed", json={"account": "@demo_tester", "post_id": "post:@demo_tester:5"})
    assert res.status_code == 404
