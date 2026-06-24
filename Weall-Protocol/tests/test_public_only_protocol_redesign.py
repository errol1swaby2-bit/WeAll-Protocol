from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from weall.api.routes_public_parts.messages import router as messages_router
from weall.api.app import create_app
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.public_protocol_policy import (
    ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED,
    GROUP_READ_VISIBILITY_MUST_BE_PUBLIC,
    PRIVATE_GROUPS_UNSUPPORTED,
    PRIVATE_MESSAGING_UNSUPPORTED,
    public_protocol_policy_violation,
)
from weall.runtime.tx_admission import admit_tx

ROOT = Path(__file__).resolve().parents[1]




class _DummyExecutor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self) -> dict:
        return self._state


def _auth(account: str = "@alice") -> dict[str, str]:
    return {"x-weall-account": account, "x-weall-session-key": "session-key"}


def _public_only_route_state() -> dict:
    return {
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "session_keys": {"session-key": {"active": True}}},
            "@bob": {"nonce": 0, "poh_tier": 2, "session_keys": {"session-key": {"active": True}}},
        },
        "content": {
            "posts": {
                "p-public": {
                    "post_id": "p-public",
                    "author": "@alice",
                    "body": "public",
                    "visibility": "public",
                    "created_nonce": 1,
                    "created_at_nonce": 1,
                    "deleted": False,
                },
                "p-private": {
                    "post_id": "p-private",
                    "author": "@alice",
                    "body": "legacy private archive",
                    "visibility": "private",
                    "created_nonce": 2,
                    "created_at_nonce": 2,
                    "deleted": False,
                },
                "p-group": {
                    "post_id": "p-group",
                    "author": "@alice",
                    "body": "legacy group visible",
                    "visibility": "group",
                    "group_id": "g-public",
                    "created_nonce": 3,
                    "created_at_nonce": 3,
                    "deleted": False,
                },
            },
            "comments": {},
            "moderation": {"targets": {}},
        },
        "groups_by_id": {
            "g-public": {"id": "g-public", "visibility": "public", "read_visibility": "public", "members": {"@alice": {}}}
        },
    }

def _ledger() -> dict:
    return {"accounts": {"@alice": {"nonce": 0, "poh_tier": 2}, "@bob": {"nonce": 0, "poh_tier": 2}}}


def _state() -> dict:
    return {
        "height": 0,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "reputation": 1000},
            "@bob": {"nonce": 0, "poh_tier": 2, "reputation": 1000},
        },
        "params": {},
    }


def _tx(tx_type: str, signer: str = "@alice", nonce: int = 1, payload: dict | None = None) -> dict:
    return {"tx_type": tx_type, "signer": signer, "nonce": nonce, "payload": payload or {}, "sig": ""}


def test_private_message_creation_is_rejected_at_admission() -> None:
    verdict = admit_tx(
        _tx(
            "DIRECT_MESSAGE_SEND",
            payload={"to": "@bob", "body": "hello"},
        ),
        _ledger(),
        canon=None,
        context="mempool",
    )
    assert verdict.ok is False
    assert verdict.code == PRIVATE_MESSAGING_UNSUPPORTED


def test_encrypted_direct_message_creation_is_rejected_at_admission() -> None:
    verdict = admit_tx(
        _tx(
            "DIRECT_MESSAGE_SEND",
            payload={
                "to": "@bob",
                "encryption": "WEALL_E2EE_V1",
                "ciphertext_b64": "ZmFrZQ==",
                "recipient_public_key": {"kty": "OKP"},
            },
        ),
        _ledger(),
        canon=None,
        context="mempool",
    )
    assert verdict.ok is False
    assert verdict.code == PRIVATE_MESSAGING_UNSUPPORTED


@pytest.mark.parametrize(
    "payload,code",
    [
        ({"group_id": "g-private", "charter": "x", "is_private": True}, PRIVATE_GROUPS_UNSUPPORTED),
        ({"group_id": "g-private", "charter": "x", "visibility": "private"}, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC),
        ({"group_id": "g-private", "charter": "x", "read_visibility": "members_only"}, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC),
    ],
)
def test_private_group_and_member_only_read_fields_are_rejected(payload: dict, code: str) -> None:
    verdict = admit_tx(_tx("GROUP_CREATE", payload=payload), _ledger(), canon=None, context="mempool")
    assert verdict.ok is False
    assert verdict.code == code


def test_public_group_content_is_stored_public_and_membership_gates_comments() -> None:
    state = _state()
    apply_tx(
        state,
        _tx(
            "GROUP_CREATE",
            nonce=1,
            payload={
                "group_id": "g-public",
                "charter": "Public Group",
                "posting_permission": "members",
                "commenting_permission": "members",
                "read_visibility": "public",
            },
        ),
    )
    apply_tx(
        state,
        _tx(
            "CONTENT_POST_CREATE",
            nonce=2,
            payload={"post_id": "p1", "group_id": "g-public", "visibility": "group", "body": "public group post"},
        ),
    )

    post = state["content"]["posts"]["p1"]
    group = state["groups_by_id"]["g-public"]
    assert post["visibility"] == "public"
    assert group["read_visibility"] == "public"
    assert group["visibility"] == "public"

    with pytest.raises(ApplyError) as denied:
        apply_tx(state, _tx("CONTENT_COMMENT_CREATE", signer="@bob", nonce=1, payload={"comment_id": "c1", "post_id": "p1", "body": "nonmember"}))
    assert denied.value.code == "forbidden"
    assert denied.value.reason == "group_comment_authority_required"

    apply_tx(state, _tx("GROUP_MEMBERSHIP_REQUEST", signer="@bob", nonce=2, payload={"group_id": "g-public"}))
    apply_tx(state, _tx("CONTENT_COMMENT_CREATE", signer="@bob", nonce=3, payload={"comment_id": "c2", "post_id": "p1", "body": "member"}))
    assert state["content"]["comments"]["c2"]["body"] == "member"


def test_group_moderation_actions_remain_public_state() -> None:
    state = _state()
    apply_tx(state, _tx("GROUP_CREATE", nonce=1, payload={"group_id": "g-public", "charter": "Public Group"}))
    apply_tx(state, _tx("GROUP_ROLE_GRANT", nonce=2, payload={"group_id": "g-public", "account": "@bob", "role": "moderators"}))
    group = state["groups_by_id"]["g-public"]
    assert group["public_only"] is True
    assert "@bob" in group["roles"]["moderators"]


def test_notification_inbox_route_is_public_event_contract_only() -> None:
    app = FastAPI()
    app.include_router(messages_router, prefix="/v1")
    client = TestClient(app)

    activity = client.get("/v1/activity/inbox")
    assert activity.status_code == 200
    body = activity.json()
    assert body["public_only"] is True
    assert body["source"] == "public_protocol_events"
    assert "direct_message" not in body.get("notice_types", [])

    legacy = client.get("/v1/messages/threads")
    assert legacy.status_code == 410
    assert legacy.json()["detail"]["code"] == PRIVATE_MESSAGING_UNSUPPORTED


def test_frontend_routes_do_not_expose_private_messaging_surface() -> None:
    router_src = (ROOT.parent / "web" / "src" / "lib" / "router.ts").read_text(encoding="utf-8")
    app_src = (ROOT.parent / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    assert 'path: "/messages"' not in router_src
    assert 'href: "/messages"' not in router_src
    assert 'case "/messages"' not in app_src
    assert 'import("./pages/Messaging")' not in app_src
    assert 'path: "/activity"' in router_src


def test_api_contract_does_not_advertise_private_message_client_methods() -> None:
    api_src = (ROOT.parent / "web" / "src" / "api" / "weall.ts").read_text(encoding="utf-8")
    route_src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "messages.py").read_text(encoding="utf-8")
    assert "messageThreads(" not in api_src
    assert "messageThread(" not in api_src
    assert "PRIVATE_MESSAGING_UNSUPPORTED" in route_src
    assert "bounded direct-message thread list" not in route_src


def test_generated_artifact_reflects_public_only_rule() -> None:
    artifact = ROOT / "generated" / "public_only_protocol_audit_v1_5.json"
    assert artifact.is_file()
    data = artifact.read_text(encoding="utf-8")
    for code in [PRIVATE_MESSAGING_UNSUPPORTED, PRIVATE_GROUPS_UNSUPPORTED, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC]:
        assert code in data
    assert "DIRECT_MESSAGE_SEND" in data
    assert "public_protocol_events" in data


def test_legacy_fixtures_cannot_reintroduce_private_or_encrypted_payloads() -> None:
    for payload, code in [
        ({"encrypted_payload": {"ciphertext": "abc"}}, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED),
        ({"metadata": {"sealed_payload": "abc"}}, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED),
        ({"attachments": [{"cid": "bafy", "ciphertext": "hidden"}]}, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED),
        ({"group_visibility": "members_only"}, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC),
    ]:
        violation = public_protocol_policy_violation(_tx("GOV_PROPOSAL_CREATE", payload=payload))
        assert violation is not None
        assert violation.code == code


def test_state_replay_rejects_encrypted_protocol_payload_deterministically() -> None:
    state = _state()
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx("GOV_PROPOSAL_CREATE", payload={"proposal_id": "p", "title": "x", "body": "x", "encrypted_payload": "opaque"}),
        )
    assert excinfo.value.code == ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED


def test_legacy_private_account_feed_and_scoped_content_archives_are_not_readable() -> None:
    app = create_app(boot_runtime=False)
    app.state.executor = _DummyExecutor(_public_only_route_state())
    client = TestClient(app)

    private_filter = client.get("/v1/accounts/@alice/feed?visibility=private", headers=_auth("@alice"))
    assert private_filter.status_code == 400
    assert private_filter.json()["error"]["code"] == GROUP_READ_VISIBILITY_MUST_BE_PUBLIC

    owner_all = client.get("/v1/accounts/@alice/feed?visibility=all", headers=_auth("@alice"))
    assert owner_all.status_code == 200, owner_all.text
    returned_ids = {str(item.get("post_id") or item.get("id")) for item in owner_all.json()["items"]}
    assert "p-public" in returned_ids
    assert "p-group" in returned_ids
    assert "p-private" not in returned_ids

    owner_scoped_private = client.get("/v1/content/p-private/scoped", headers=_auth("@alice"))
    assert owner_scoped_private.status_code == 404

    anon_group_detail = client.get("/v1/content/p-group")
    assert anon_group_detail.status_code == 200, anon_group_detail.text
    assert anon_group_detail.json()["content"]["post_id"] == "p-group"
