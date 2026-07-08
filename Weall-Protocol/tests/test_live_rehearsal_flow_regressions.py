from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.reputation_events import append_reputation_event
from weall.runtime.reviewer_responsibilities import reviewer_lane_active


class _FakeExecutor:
    def __init__(self, state: dict) -> None:
        self._state = state

    def read_state(self) -> dict:
        return self._state

    def snapshot(self) -> dict:
        return self._state


def _client(state: dict) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def test_reviewer_lane_opt_in_has_no_second_activation_limbo() -> None:
    state = {
        "accounts": {"@observer": {"poh_tier": 2, "banned": False, "locked": False}},
        "roles": {
            "jurors": {
                "active_set": ["@observer"],
                "by_id": {
                    "@observer": {
                        "active": True,
                        "status": "active",
                        "responsibilities": {
                            "reviewer": {
                                "poh_live_review": {
                                    "opted_in": True,
                                    "active": False,
                                    "status": "opted_in_inactive",
                                }
                            }
                        },
                    }
                },
            }
        },
    }

    assert reviewer_lane_active(state, "@observer", "poh_live_review") is True
    body = _client(state).get("/v1/accounts/%40observer/reviewer-status").json()
    lane = body["reviewer"]["lanes"]["poh_live_review"]
    assert lane["opted_in"] is True
    assert lane["active"] is True
    assert lane["status"] == "active"
    assert body["reviewer"]["active_lanes"] == ["poh_live_review"]


def test_reputation_progression_uses_event_sourced_public_aggregate_not_stale_scalar() -> None:
    state = {"height": 58, "accounts": {"@observer": {"poh_tier": 2, "reputation_milli": 0, "banned": False, "locked": False}}}
    append_reputation_event(
        state,
        actor_id="@observer",
        event_code="POH_TIER2_APPROVED",
        source_flow="poh",
        source_tx_id="tx:poh:approved",
        source_object_id="poh:@observer",
        occurred_at_block=58,
    )

    body = _client(state).get("/v1/accounts/%40observer/reputation-progression-status").json()
    assert body["ok"] is True
    assert body["reputation_total_milli"] >= 1000
    thresholds = {row["name"]: row for row in body["next_relevant_thresholds"]}
    assert thresholds["baseline_civic_participation"]["actual_milli"] == body["reputation_total_milli"]
    assert thresholds["validator_reputation_readiness"]["actual_milli"] == body["reputation_total_milli"]
