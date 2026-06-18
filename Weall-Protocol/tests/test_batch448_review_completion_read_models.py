from __future__ import annotations

from pathlib import Path
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

    def tx_index_hash(self) -> str:
        return "batch448-tx-index"


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def _auth(account: str) -> dict[str, str]:
    return {"x-weall-account": account, "x-weall-session-key": f"sk:{account}"}


def _account_state(*accounts: str) -> dict[str, Any]:
    return {
        acct: {
            "nonce": 0,
            "poh_tier": 2,
            "banned": False,
            "locked": False,
            "session_keys": {f"sk:{acct}": {"active": True, "ttl_s": 0}},
        }
        for acct in accounts
    }


def _content_state_with_removed_post() -> dict[str, Any]:
    return {
        "chain_id": "batch448",
        "accounts": _account_state("@alice", "@reviewer"),
        "content": {
            "posts": {
                "post:1": {
                    "id": "post:1",
                    "post_id": "post:1",
                    "author": "@alice",
                    "body": "reported post",
                    "visibility": "public",
                    "created_nonce": 12,
                    "created_at_nonce": 12,
                },
                "post:2": {
                    "id": "post:2",
                    "post_id": "post:2",
                    "author": "@alice",
                    "body": "kept post",
                    "visibility": "public",
                    "created_nonce": 13,
                    "created_at_nonce": 13,
                },
            },
            "comments": {},
            "reactions": {},
            "moderation": {
                "targets": {
                    "post:1": {
                        "target_id": "post:1",
                        "visibility": "deleted",
                        "last_action": "remove",
                        "deleted": True,
                    }
                }
            },
        },
        "disputes_by_id": {
            "dispute:1": {
                "id": "dispute:1",
                "stage": "appeal_window",
                "target_type": "content",
                "target_id": "post:1",
                "target_owner": "@alice",
                "appeal_allowed_accounts": ["@alice"],
                "opened_by": "@reviewer",
                "reason": "test report",
                "jurors": {"@reviewer": {"status": "accepted", "attendance": {"present": True}}},
                "votes": {"@reviewer": {"vote": "yes"}},
                "evidence": [],
                "appeals": [],
                "resolved": True,
                "resolution": {"outcome": "report_upheld"},
                "appeal_deadline_height": 99,
            }
        },
    }


def test_batch448_removed_content_is_hidden_from_public_and_account_feeds() -> None:
    client = _client(_content_state_with_removed_post())

    public_feed = client.get("/v1/feed?limit=10").json()["items"]
    account_feed = client.get("/v1/accounts/%40alice/feed?limit=10", headers=_auth("@alice")).json()["items"]

    assert [item["post_id"] for item in public_feed] == ["post:2"]
    assert [item["post_id"] for item in account_feed] == ["post:2"]

    detail = client.get("/v1/content/post%3A1", headers=_auth("@alice"))
    assert detail.status_code == 404


def test_batch448_creator_appeal_eligibility_survives_hidden_content_and_reviewer_cannot_file() -> None:
    client = _client(_content_state_with_removed_post())

    creator = client.get("/v1/disputes/dispute%3A1", headers=_auth("@alice"))
    reviewer = client.get("/v1/disputes/dispute%3A1", headers=_auth("@reviewer"))

    assert creator.status_code == 200, creator.text
    assert reviewer.status_code == 200, reviewer.text

    creator_dispute = creator.json()["dispute"]
    reviewer_dispute = reviewer.json()["dispute"]

    assert creator_dispute["target_owner"] == "@alice"
    assert creator_dispute["appeal_allowed_accounts"] == ["@alice"]
    assert creator_dispute["appeal_eligibility"]["can_file"] is True
    assert creator_dispute["appeal_eligibility"]["reason"] == "eligible_target_owner"

    assert reviewer_dispute["appeal_eligibility"]["can_file"] is False
    assert reviewer_dispute["appeal_eligibility"]["reason"] == "not_target_owner"


def _poh_state() -> dict[str, Any]:
    return {
        "chain_id": "batch448",
        "accounts": _account_state("@genesis", "@alice"),
        "roles": {"jurors": {"active_set": ["@genesis"]}},
        "poh": {
            "async_cases": {
                "async:done": {
                    "case_id": "async:done",
                    "account_id": "@alice",
                    "status": "approved",
                    "assigned_jurors": ["@genesis"],
                    "jurors": {"@genesis": {"status": "accepted"}},
                    "receipt": {"ok": True},
                    "finalized_height": 10,
                },
                "async:open": {
                    "case_id": "async:open",
                    "account_id": "@alice",
                    "status": "open",
                    "assigned_jurors": ["@genesis"],
                    "jurors": {"@genesis": {"status": "accepted"}},
                    "evidence_commitments": {"ev:1": "sha256:abc"},
                    "evidence_binds": {"ev:1": "async:open"},
                },
            },
            "tier2_cases": {
                "tier2:done": {
                    "account_id": "@alice",
                    "status": "finalized",
                    "jurors": {"@genesis": {"status": "accepted"}},
                    "outcome": "pass",
                    "finalized_ts_ms": 123,
                },
                "tier2:open": {
                    "account_id": "@alice",
                    "status": "open",
                    "jurors": {"@genesis": {"status": "accepted"}},
                },
            },
            "live_cases": {
                "live:done": {
                    "account_id": "@alice",
                    "status": "passed",
                    "jurors": {"@genesis": {"status": "accepted"}},
                    "outcome": "pass",
                    "finalized_ts_ms": 456,
                },
                "live:open": {
                    "account_id": "@alice",
                    "status": "open",
                    "jurors": {"@genesis": {"status": "accepted"}},
                },
            },
        },
    }


def test_batch448_completed_poh_cases_leave_active_reviewer_queues_by_default() -> None:
    client = _client(_poh_state())

    async_default = client.get("/v1/poh/async/juror-cases?juror=%40genesis").json()["cases"]
    async_all = client.get("/v1/poh/async/juror-cases?juror=%40genesis&include_completed=1").json()["cases"]
    assert [case["case_id"] for case in async_default] == ["async:open"]
    assert [case["case_id"] for case in async_all] == ["async:done", "async:open"]

    tier2_default = client.get("/v1/poh/tier2/juror-cases?juror=%40genesis").json()["cases"]
    tier2_all = client.get("/v1/poh/tier2/juror-cases?juror=%40genesis&include_completed=1").json()["cases"]
    assert [case["case_id"] for case in tier2_default] == ["tier2:open"]
    assert [case["case_id"] for case in tier2_all] == ["tier2:done", "tier2:open"]

    live_default = client.get("/v1/poh/live/assigned?juror=%40genesis").json()["cases"]
    live_all = client.get("/v1/poh/live/assigned?juror=%40genesis&include_completed=1").json()["cases"]
    assert [case["case_id"] for case in live_default] == ["live:open"]
    assert [case["case_id"] for case in live_all] == ["live:done", "live:open"]

    removed = client.get("/v1/poh/live/juror-cases?juror=%40genesis")
    assert removed.status_code == 410
    assert removed.json()["error"]["code"] == "legacy_endpoint_removed"


def test_batch448_frontend_uses_viewer_auth_and_filters_completed_review_work() -> None:
    root = Path(__file__).resolve().parents[2]
    dispute_detail = (root / "web" / "src" / "pages" / "DisputeDetail.tsx").read_text(encoding="utf-8")
    pending_work = (root / "web" / "src" / "lib" / "pendingWork.ts").read_text(encoding="utf-8")
    juror_dashboard = (root / "web" / "src" / "pages" / "JurorDashboard.tsx").read_text(encoding="utf-8")

    assert "const headers = account ? getAuthHeaders(account) : undefined;" in dispute_detail
    assert "weall.dispute(id, apiBase, headers)" in dispute_detail
    assert "weall.disputeVotes(id, apiBase, headers)" in dispute_detail

    assert "function reportStageNeedsReviewerAction" in pending_work
    assert "if (vote || !reportStageNeedsReviewerAction(stage)) return null;" in pending_work

    assert "function reportNeedsCurrentReviewer" in juror_dashboard
    assert "if (disputeCurrentVote(item, account)) return false;" in juror_dashboard
    assert "if (!reportStageNeedsReviewerAction(item?.stage || item?.status)) return false;" in juror_dashboard
