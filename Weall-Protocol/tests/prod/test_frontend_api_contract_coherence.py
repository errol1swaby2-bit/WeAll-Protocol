from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def test_reviewer_status_is_backend_truth_source_for_frontend_lanes() -> None:
    state = {
        "accounts": {
            "@alice": {"poh_tier": 2, "reputation": 1, "banned": False, "locked": False, "nonce": 0},
        },
        "roles": {
            "jurors": {
                "active_set": ["@alice"],
                "by_id": {
                    "@alice": {
                        "active": True,
                        "responsibilities": {
                            "reviewer": {
                                "content_review": {"opted_in": True, "active": True},
                                "dispute_review": {"opted_in": False, "active": False},
                                "poh_async_review": {"opted_in": True, "active": True},
                                "poh_live_review": {"opted_in": False, "active": False},
                            }
                        },
                    }
                },
            }
        },
    }
    client = _client(state)
    res = client.get("/v1/accounts/%40alice/reviewer-status")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    reviewer = body["reviewer"]
    assert reviewer["backend_source_of_truth"] is True
    assert reviewer["policy"] == "exact_lane_opt_in_required"
    assert reviewer["eligible"] is True
    assert reviewer["active"] is True
    assert reviewer["lanes"]["content_review"]["active"] is True
    assert reviewer["lanes"]["dispute_review"]["active"] is False
    assert reviewer["lanes"]["poh_async_review"]["active"] is True
    assert reviewer["active_lanes"] == ["content_review", "poh_async_review"]


def test_reviewer_status_reports_eligibility_blockers_without_frontend_guessing() -> None:
    client = _client({"accounts": {"@bob": {"poh_tier": 1, "banned": False, "locked": True}}, "roles": {"jurors": {"active_set": [], "by_id": {}}}})
    res = client.get("/v1/accounts/%40bob/reviewer-status")
    assert res.status_code == 200, res.text
    reviewer = res.json()["reviewer"]
    assert reviewer["eligible"] is False
    assert "trusted_verified_person_required" in reviewer["eligibility_blockers"]
    assert "account_locked" in reviewer["eligibility_blockers"]
    assert all(lane["active"] is False for lane in reviewer["lanes"].values())
