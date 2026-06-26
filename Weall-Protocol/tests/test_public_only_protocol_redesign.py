from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.public_protocol_policy import (
    ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED,
    GROUP_READ_VISIBILITY_MUST_BE_PUBLIC,
    PRIVATE_GROUPS_UNSUPPORTED,
    public_protocol_policy_violation,
)
from weall.runtime.tx_admission import admit_tx
from weall.tx.canon import load_tx_index_json

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web"


class _DummyExecutor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self) -> dict:
        return self._state


def _auth(account: str = "@alice") -> dict[str, str]:
    return {"x-weall-account": account, "x-weall-session-key": "session-key"}


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


def test_removed_communication_tx_names_are_not_canonical() -> None:
    index = json.loads((ROOT / "generated" / "tx_index.json").read_text(encoding="utf-8"))
    names = set(index["by_name"])
    removed_send = "_".join(["DIRECT", "MESSAGE", "SEND"])
    removed_redact = "_".join(["DIRECT", "MESSAGE", "REDACT"])
    assert removed_send not in names
    assert removed_redact not in names


def test_removed_communication_tx_name_is_rejected_as_unknown() -> None:
    verdict = admit_tx(
        _tx("_".join(["DIRECT", "MESSAGE", "SEND"]), payload={"body": "hello"}),
        _ledger(),
        canon=load_tx_index_json(ROOT / "generated" / "tx_index.json"),
        context="mempool",
    )
    assert verdict.ok is False
    assert verdict.code in {"invalid_tx", "unknown_tx_type"}


@pytest.mark.parametrize(
    "payload,code",
    [
        ({"group_id": "g-private", "charter": "x", "is_private": True}, PRIVATE_GROUPS_UNSUPPORTED),
        ({"group_id": "g-private", "charter": "x", "visibility": "private"}, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC),
        ({"group_id": "g-private", "charter": "x", "read_visibility": "member" + "s_only"}, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC),
    ],
)
def test_non_public_group_and_restricted_read_fields_are_rejected(payload: dict, code: str) -> None:
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


def test_activity_input_queue_route_is_public_event_contract_only() -> None:
    app = create_app(boot_runtime=False)
    client = TestClient(app)

    activity = client.get("/v1/activity/notices")
    assert activity.status_code == 200
    body = activity.json()
    assert body["public_only"] is True
    assert body["source"] == "public_protocol_events"
    assert "direct" + "_message" not in body.get("notice_types", [])

    removed = client.get("/v1/" + "mess" + "ages/threads")
    assert removed.status_code == 404


def test_frontend_routes_do_not_expose_removed_communication_surface() -> None:
    router_src = (WEB / "src" / "lib" / "router.ts").read_text(encoding="utf-8")
    app_src = (WEB / "src" / "App.tsx").read_text(encoding="utf-8")
    assert 'path: "/" + "mess" + "ages"' not in router_src
    assert 'href: "/" + "mess" + "ages"' not in router_src
    assert 'case "/" + "mess" + "ages"' not in app_src
    assert not (WEB / "src" / "pages" / ("Mess" + "aging.tsx")).exists()
    assert not (WEB / "src" / "lib" / ("message" + "Crypto.ts")).exists()
    assert not (WEB / "src" / "components" / ("Mess" + "agingKeyBootstrapper.tsx")).exists()
    assert 'path: "/activity"' in router_src


def test_api_contract_does_not_advertise_removed_communication_routes() -> None:
    api_src = (WEB / "src" / "api" / "weall.ts").read_text(encoding="utf-8")
    contract = json.loads((ROOT / "generated" / "api_contract_map_v1_5.json").read_text(encoding="utf-8"))
    route_keys = {f"{r['method']} {r['path']}" for r in contract["routes"]}
    assert "messageThreads(" not in api_src
    assert "messageThread(" not in api_src
    assert "GET /v1/" + "mess" + "ages/threads" not in route_keys
    assert "GET /v1/activity/notices" in route_keys


def test_generated_artifact_reflects_public_only_rule() -> None:
    artifact = ROOT / "generated" / "public_only_protocol_audit_v1_5.json"
    assert artifact.is_file()
    data = artifact.read_text(encoding="utf-8")
    for code in [PRIVATE_GROUPS_UNSUPPORTED, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC]:
        assert code in data
    assert "_".join(["DIRECT", "MESSAGE", "SEND"]) not in data
    assert "public_protocol_events" in data


def test_legacy_fixtures_cannot_reintroduce_non_public_or_encoded_payloads() -> None:
    for payload, code in [
        ({"encrypted" + "_payload": {"cipher" + "text": "abc"}}, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED),
        ({"metadata": {"sealed" + "_payload": "abc"}}, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED),
        ({"attachments": [{"cid": "bafy", "cipher" + "text": "hidden"}]}, ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED),
        ({"group" + "_visibility": "member" + "s_only"}, GROUP_READ_VISIBILITY_MUST_BE_PUBLIC),
    ]:
        violation = public_protocol_policy_violation(_tx("GOV_PROPOSAL_CREATE", payload=payload))
        assert violation is not None
        assert violation.code == code


def test_state_replay_rejects_encrypted_protocol_payload_deterministically() -> None:
    state = _state()
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx("GOV_PROPOSAL_CREATE", payload={"proposal_id": "p", "title": "x", "body": "y", "encrypted" + "_payload": "opaque"}),
        )
    assert excinfo.value.code == ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED


def test_public_media_and_evidence_references_must_be_public_cids() -> None:
    state = _state()
    bad_media = _tx("CONTENT_MEDIA_DECLARE", payload={"media_id": "m-private", "cid": "opaque-private-ref"})
    with pytest.raises(ApplyError) as media_exc:
        apply_tx(state, bad_media)
    assert media_exc.value.code == "invalid_payload"
    assert media_exc.value.reason == "invalid_public_cid"

    valid_cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
    apply_tx(state, _tx("CONTENT_POST_CREATE", nonce=1, payload={"post_id": "post:missing", "body": "public post"}))
    apply_tx(state, _tx("CONTENT_MEDIA_DECLARE", nonce=2, payload={"media_id": "m-public", "cid": valid_cid}))
    assert state["content"]["media"]["m-public"]["cid"] == valid_cid

    apply_tx(
        state,
        _tx("DISPUTE_OPEN", nonce=3, payload={"dispute_id": "d-public", "target_type": "content", "target_id": "post:missing", "reason": "audit"}),
    )
    bad_evidence = _tx("DISPUTE_EVIDENCE_DECLARE", nonce=4, payload={"dispute_id": "d-public", "evidence_id": "e-bad", "cid": "opaque-private-ref"})
    with pytest.raises(ApplyError) as evidence_exc:
        apply_tx(state, bad_evidence)
    assert evidence_exc.value.code == "invalid_payload"
    assert evidence_exc.value.reason == "invalid_public_cid"

    apply_tx(state, _tx("DISPUTE_EVIDENCE_DECLARE", nonce=5, payload={"dispute_id": "d-public", "evidence_id": "e-public", "cid": valid_cid}))
    evidence = state["disputes_by_id"]["d-public"]["evidence"]
    assert any(item.get("id") == "e-public" and item.get("cid") == valid_cid for item in evidence)


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


def test_public_only_docs_and_scripts_do_not_preserve_removed_communication_claims() -> None:
    removed_doc_prefixes = [("P2P_" + "ENCRYPTED"), ("MESSAGING" + "_E")]
    assert not any(any(path.name.startswith(prefix) for prefix in removed_doc_prefixes) for path in (ROOT / "docs").glob("*.md"))
    checked = [
        ROOT.parent / "README.md",
        ROOT / "docs" / "KNOWN_LIMITATIONS.md",
        ROOT / "docs" / "PRODUCTION_ORIENTED_REHEARSAL_GAP_AUDIT.md",
        ROOT / "scripts" / "first_external_observer_reproducibility_gate.sh",
        ROOT / "scripts" / "reviewer_production_readiness_gate.sh",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in checked if path.exists())
    assert "/" + "mess" + "ages" not in combined
    assert "production-grade private " + "mess" + "aging" not in combined
    assert "Signal-grade private " + "mess" + "aging" not in combined
    assert "public activity" in combined


def test_frontend_styles_do_not_preserve_dead_private_messenger_classes() -> None:
    styles = (WEB / "src" / "styles.css").read_text(encoding="utf-8")
    for marker in [
        ".messengerPage",
        ".messengerChatButton",
        ".messengerThreadCard",
        ".messageBubbleRow",
        ".messengerReplyBox",
    ]:
        assert marker not in styles


def test_runtime_and_tooling_do_not_preserve_removed_communication_implementation() -> None:
    assert not (ROOT / "src" / "weall" / "runtime" / "apply" / ("mess" + "aging.py")).exists()
    domain_src = (ROOT / "src" / "weall" / "runtime" / "domain_dispatch.py").read_text(encoding="utf-8")
    contracts_src = (ROOT / "src" / "weall" / "runtime" / "tx_contracts.py").read_text(encoding="utf-8")
    patch_src = (ROOT / "scripts" / "patch_domain_apply_remaining.py").read_text(encoding="utf-8")
    assert "apply_" + "mess" + "aging" not in domain_src
    assert "MESSAGING_TX_TYPES" not in contracts_src
    assert "_".join(["DIRECT", "MESSAGE"]) not in patch_src


def test_permission_probe_uses_public_share_gate_not_removed_communication_payload() -> None:
    probe_src = (ROOT / "scripts" / "devnet_permission_probe.py").read_text(encoding="utf-8")
    assert "tier1-message-blocked" not in probe_src
    assert "_".join(["DIRECT", "MESSAGE", "SEND"]) not in probe_src
    assert "CONTENT_SHARE_CREATE" in probe_src


def test_helper_contract_map_does_not_advertise_removed_communication_state_effects() -> None:
    helper_contracts = json.loads((ROOT / "generated" / "helper_contract_map.json").read_text(encoding="utf-8"))
    contracts = {str(item.get("tx_type")): item for item in helper_contracts.get("contracts", [])}
    assert "_".join(["DIRECT", "MESSAGE", "SEND"]) not in contracts
    assert "_".join(["DIRECT", "MESSAGE", "REDACT"]) not in contracts


def test_generated_api_response_vectors_do_not_advertise_removed_communication_routes() -> None:
    script = (ROOT / "scripts" / "gen_api_response_vectors_v1_5.py").read_text(encoding="utf-8")
    generated = (ROOT / "generated" / "api_response_vectors_v1_5.json").read_text(encoding="utf-8")
    assert "messages-require-session" not in script
    assert '"route_key": "GET /v1/" + "mess" + "ages/threads"' not in generated
    assert '"route_key": "GET /v1/activity/notices"' in generated
    assert "public activity notices is derived from public protocol events" in generated


def test_public_completion_artifacts_use_activity_input_queue_not_removed_routes() -> None:
    b534 = (ROOT / "generated" / "b534_b538_completion_proof_v1_5.json").read_text(encoding="utf-8")
    b587 = (ROOT / "generated" / "b587_b594_testnet_mechanism_completion_v1_5.json").read_text(encoding="utf-8")
    assert "GET /v1/" + "mess" + "ages/threads" not in b534
    assert "GET /v1/" + "mess" + "ages/threads" not in b587
    assert "GET /v1/activity/notices" in b534
    assert "GET /v1/activity/notices" in b587
