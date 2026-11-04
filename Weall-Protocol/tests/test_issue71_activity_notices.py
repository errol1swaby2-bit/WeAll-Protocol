"""Issue #71: public-event notices have explicit recipients and stable read-only IDs."""

from __future__ import annotations

import copy
import json

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.routes_public_parts import activity
from weall.api.routes_public_parts.activity import collect_public_activity_notices


def _snapshot() -> dict:
    return {
        "chain_id": "test-chain",
        "genesis_hash": "test-genesis",
        "height": 22,
        "notify": {
            "emit_receipts": [
                {
                    "at_nonce": 8,
                    "payload": {
                        "receipt_id": "notice-a",
                        "account_id": "@alice",
                        "topic": "review_assignment",
                    },
                },
                {
                    "at_nonce": 9,
                    "payload": {
                        "receipt_id": "notice-b",
                        "account_id": "@alicia",
                        "topic": "security",
                    },
                },
            ]
        },
        "reputation": {
            "events": [
                {
                    "event_id": "rep-a",
                    "actor_id": "@alice",
                    "event_code": "DISPUTE_REVIEW_COMPLETED",
                    "occurred_at_block": 20,
                    "severity": 1,
                    "details": {"private_evidence_key": "do-not-include"},
                }
            ]
        },
        "disputes_by_id": {
            "case-a": {"dispute_id": "case-a", "jurors": {"@alice": {"active": True}}},
            "case-other": {"dispute_id": "case-other", "jurors": {"@alicia": {}}},
        },
        "content": {
            "posts_by_id": {"post-with-text": {"body": "hello @alice", "author": "@alicia"}}
        },
    }


def test_projector_is_exact_recipient_only_and_does_not_read_arbitrary_text() -> None:
    state = _snapshot()
    before = json.dumps(state, sort_keys=True)
    notices = collect_public_activity_notices(state, "@alice")
    assert {item["type"] for item in notices} == {
        "dispute_assignment",
        "reputation_update",
    }
    assert len(notices) == 3
    assert all("@alicia" not in item["id"] for item in notices)
    assert "do-not-include" not in json.dumps(notices)
    assert json.dumps(state, sort_keys=True) == before
    assert notices == collect_public_activity_notices(copy.deepcopy(state), "@alice")


def test_projector_dedupes_replayed_receipt_id_and_keeps_stable_order() -> None:
    state = _snapshot()
    state["notify"]["emit_receipts"].append(copy.deepcopy(state["notify"]["emit_receipts"][0]))
    notices = collect_public_activity_notices(state, "@alice")
    assert len(notices) == 3
    ids = [item["id"] for item in notices]
    assert len(ids) == len(set(ids))
    assert ids[0].startswith("reputation:")
    assert ids == [item["id"] for item in collect_public_activity_notices(state, "@alice")]


def test_similar_but_distinct_account_id_has_no_false_positive() -> None:
    notices = collect_public_activity_notices(_snapshot(), "@ali")
    assert notices == []


def test_unauthed_route_retains_public_type_contract_without_state_read() -> None:
    client = TestClient(create_app(boot_runtime=False))
    result = client.get("/v1/activity/notices")
    assert result.status_code == 200
    payload = result.json()
    assert payload["public_only"] is True
    assert payload["authenticated"] is False
    assert payload["items"] == []


def test_authenticated_route_reads_deterministic_page_and_rejects_bad_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _snapshot()
    monkeypatch.setattr(activity, "_snapshot", lambda _: state)
    monkeypatch.setattr(activity, "require_account_session", lambda _req, _st: "@alice")
    client = TestClient(create_app(boot_runtime=False))
    headers = {"x-weall-account": "@alice", "x-weall-session-key": "test"}
    first = client.get("/v1/activity/notices?limit=1", headers=headers)
    assert first.status_code == 200
    data = first.json()
    assert data["authenticated"] is True
    assert data["account_id"] == "@alice"
    assert data["chain_id"] == "test-chain"
    assert len(data["items"]) == 1
    assert data["next_cursor"] == data["items"][0]["id"]
    second = client.get(
        "/v1/activity/notices",
        headers=headers,
        params={"cursor": data["next_cursor"]},
    )
    assert second.status_code == 200
    assert len(second.json()["items"]) == 2
    invalid = client.get(
        "/v1/activity/notices",
        headers=headers,
        params={"cursor": "does-not-exist"},
    )
    assert invalid.status_code == 400


def test_invalid_authenticated_session_is_not_silent_empty_inbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(activity, "_snapshot", lambda _: _snapshot())

    def deny(_request: object, _state: object) -> str:
        raise PermissionError("session_invalid")

    monkeypatch.setattr(activity, "require_account_session", deny)
    client = TestClient(create_app(boot_runtime=False))
    result = client.get(
        "/v1/activity/notices",
        headers={"x-weall-account": "@alice", "x-weall-session-key": "invalid"},
    )
    assert result.status_code == 401
    assert result.json()["detail"]["code"] == "invalid_session"


def test_public_reply_is_derived_from_parent_ownership_not_body_substrings() -> None:
    state = _snapshot()
    state["content"] = {
        "posts": {
            "owned": {"author": "@alice", "visibility": "public", "deleted": False},
            "other": {"author": "@alicia", "visibility": "public", "deleted": False},
        },
        "comments": {
            "real": {
                "comment_id": "real",
                "post_id": "owned",
                "author": "@bob",
                "visibility": "public",
                "deleted": False,
                "body": "Thanks!",
            },
            "not-mine": {
                "comment_id": "not-mine",
                "post_id": "other",
                "author": "@bob",
                "visibility": "public",
                "deleted": False,
                "body": "@alice",
            },
            "self": {
                "comment_id": "self",
                "post_id": "owned",
                "author": "@alice",
                "visibility": "public",
                "deleted": False,
            },
            "deleted": {
                "comment_id": "deleted",
                "post_id": "owned",
                "author": "@bob",
                "visibility": "public",
                "deleted": True,
            },
        },
    }
    replies = [
        item for item in collect_public_activity_notices(state, "@alice") if item["type"] == "reply"
    ]
    assert len(replies) == 1
    assert replies[0]["id"] == "reply:real:@alice"
    assert replies[0]["href"] == "/thread/owned"


def test_governance_status_notice_requires_exact_proposal_creator_and_terminal_stage() -> None:
    state = _snapshot()
    state["gov_proposals_by_id"] = {
        "p-1": {"proposal_id": "p-1", "creator": "@alice", "stage": "tallied"},
        "p-2": {"proposal_id": "p-2", "creator": "@alicia", "stage": "finalized"},
        "p-3": {"proposal_id": "p-3", "creator": "@alice", "stage": "draft"},
        "p-4": {"proposal_id": "p-4", "creator": "@alice", "stage": "executed"},
    }
    before = json.dumps(state, sort_keys=True)
    notices = [
        item
        for item in collect_public_activity_notices(state, "@alice")
        if item["type"] == "governance_notice"
    ]
    assert {item["id"] for item in notices} == {
        "governance-stage:p-1:tallied:@alice",
        "governance-stage:p-4:executed:@alice",
    }
    assert {item["href"] for item in notices} == {"/decisions/p-1", "/decisions/p-4"}
    assert json.dumps(state, sort_keys=True) == before
    assert notices == [
        item
        for item in collect_public_activity_notices(state, "@alice")
        if item["type"] == "governance_notice"
    ]
