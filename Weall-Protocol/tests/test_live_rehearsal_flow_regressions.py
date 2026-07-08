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


def _content_review_assignment_state() -> dict:
    return {
        "height": 43,
        "accounts": {
            "@devnet-genesis": {"poh_tier": 2, "banned": False, "locked": False},
            "@observer": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {
            "jurors": {
                "active_set": ["@observer"],
                "by_id": {
                    "@observer": {
                        "active": True,
                        "status": "active",
                        "responsibilities": {
                            "reviewer": {
                                "content_review": {"opted_in": True, "active": True, "status": "active"},
                                "dispute_review": {"opted_in": True, "active": True, "status": "active"},
                            }
                        },
                    }
                },
            }
        },
        "content": {
            "posts": {
                "post:@devnet-genesis:15": {
                    "id": "post:@devnet-genesis:15",
                    "post_id": "post:@devnet-genesis:15",
                    "author": "@devnet-genesis",
                    "body": "reported post",
                    "visibility": "public",
                }
            },
            "comments": {},
        },
        "disputes_by_id": {
            "dispute:SYSTEM:0": {
                "id": "dispute:SYSTEM:0",
                "stage": "unassigned",
                "target_type": "content",
                "target_id": "post:@devnet-genesis:15",
                "target_owner": "@devnet-genesis",
                "assignment_blocked_reason": "no_unconflicted_content_reviewer",
                "jurors": {},
                "assigned_jurors": [],
                "eligible_juror_ids": [],
            }
        },
        "system_queue": [],
    }


def test_unassigned_content_report_scheduler_selects_only_unconflicted_reviewer() -> None:
    from weall.runtime.domain_dispatch import apply_tx
    from weall.runtime.system_tx_engine import system_tx_emitter
    from weall.tx.canon import TxIndex

    state = _content_review_assignment_state()
    canon = TxIndex.load_from_file("generated/tx_index.json")

    emitted = system_tx_emitter(state, canon, next_height=44, phase="post")
    assign = [env for env in emitted if env.tx_type == "DISPUTE_JUROR_ASSIGN"]
    assert len(assign) == 1
    assert assign[0].payload["dispute_id"] == "dispute:SYSTEM:0"
    assert assign[0].payload["juror"] == "@observer"
    assert assign[0].payload["assignment_source"] == "content_review_assignment_scheduler"

    apply_tx(state, assign[0])
    dispute = state["disputes_by_id"]["dispute:SYSTEM:0"]
    assert dispute["stage"] == "juror_review"
    assert dispute["assigned_jurors"] == ["@observer"]
    assert dispute["eligible_juror_ids"] == ["@observer"]
    assert "@devnet-genesis" not in dispute["assigned_jurors"]


def test_unassigned_content_report_scheduler_does_not_assign_target_owner() -> None:
    from weall.runtime.system_tx_engine import system_tx_emitter
    from weall.tx.canon import TxIndex

    state = _content_review_assignment_state()
    state["roles"]["jurors"]["active_set"] = ["@devnet-genesis"]
    state["roles"]["jurors"]["by_id"] = {
        "@devnet-genesis": {
            "active": True,
            "status": "active",
            "responsibilities": {"reviewer": {"content_review": {"opted_in": True, "active": True, "status": "active"}}},
        }
    }
    canon = TxIndex.load_from_file("generated/tx_index.json")
    emitted = system_tx_emitter(state, canon, next_height=44, phase="post")
    assert [env.tx_type for env in emitted if env.tx_type == "DISPUTE_JUROR_ASSIGN"] == []
