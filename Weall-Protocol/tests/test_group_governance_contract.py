from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    chain_id = "testnet-group-contract"

    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _state() -> dict[str, Any]:
    return {
        "chain_id": "testnet-group-contract",
        "height": 12,
        "accounts": {
            "@alice": {"nonce": 1, "poh_tier": 2, "session_keys": {"alice-session": {"active": True}}},
            "@bob": {"nonce": 1, "poh_tier": 2},
        },
        "groups_by_id": {
            "g:civic": {
                "group_id": "g:civic",
                "id": "g:civic",
                "charter": "Civic builders\n\nPublic coordination group.",
                "members": {"@alice": {"role": "member"}},
                "membership_requests": {"@bob": {"requested_at_nonce": 7}},
                "permissions": {
                    "read": "public",
                    "post": "members",
                    "comment": "members",
                    "vote": "members",
                    "moderate": "moderators",
                    "admin": "admins",
                },
                "signers": ["@alice", "@bob"],
                "threshold": 2,
                "moderators": ["@alice"],
                "meta": {"visibility": "public"},
            }
        },
        "group_emissary_elections": {
            "election:1": {
                "election_id": "election:1",
                "group_id": "g:civic",
                "status": "open",
                "candidates": ["@alice", "@bob"],
            }
        },
        "content": {"posts": {}, "comments": {}, "media": {}, "reactions": {}},
    }


def test_group_governance_contract_is_public_derived_product_contract() -> None:
    with _client(_state()) as client:
        res = client.get("/v1/groups/g:civic/governance-contract")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["object_classification"] == "public_derived_index_view"
    assert body["governance_model"] == "protocol_governance_scaled_to_group_scope"
    assert body["public_only_contract"]["read_visibility"] == "public"
    assert body["public_only_contract"]["content_read_gated_by_membership"] is False
    assert body["public_only_contract"]["private_groups_supported"] is False
    assert body["public_only_contract"]["member_only_read_supported"] is False
    assert body["authority_contract"]["admin_shortcuts_supported"] is False
    assert body["authority_contract"]["frontend_caches_are_authoritative"] is False
    assert body["authority_contract"]["role_mutations_are_public"] is True
    assert body["authority_contract"]["signer_threshold"] == 2
    assert body["counts"] == {
        "members": 1,
        "membership_requests": 1,
        "signers": 2,
        "moderators": 1,
        "active_elections": 1,
    }
    assert body["tx_entrypoints"]["request_membership"]["tx_type"] == "GROUP_MEMBERSHIP_REQUEST"
    assert body["tx_entrypoints"]["group_ballot_cast"]["tx_type"] == "GROUP_EMISSARY_BALLOT_CAST"
    assert body["inspection_routes"]["tx_status"] == "/v1/tx/status/{tx_id}"


def test_group_governance_contract_missing_group_is_not_hidden_state() -> None:
    with _client(_state()) as client:
        res = client.get("/v1/groups/g:missing/governance-contract")

    assert res.status_code == 404, res.text
    body = res.json()
    assert body["error"]["code"] == "not_found"
    assert body["error"]["details"]["group_id"] == "g:missing"
