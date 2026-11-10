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
            "@alice": {
                "nonce": 1,
                "poh_tier": 2,
                "session_keys": {"alice-session": {"active": True}},
            },
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



def _election_state() -> dict[str, Any]:
    state = _state()
    state["groups_by_id"]["g:other"] = {"id": "g:other", "members": {"@bob": {}}}
    state["group_emissary_elections"] = {
        "e:open": {
            "election_id": "e:open", "group_id": "g:civic", "status": "open",
            "candidates": ["@bob", "@alice"], "voter_snapshot": ["@alice"],
            "seats": 5, "start_height": 10, "end_height": 50, "created_at_height": 9,
            "payload": {"secret_note": "never_publish"},
            "ballots": {"@alice": {"ranking": ["@bob"]}},
            "nullifiers": {"private": "never_publish"},
        },
        "e:empty": {
            "election_id": "e:empty", "group_id": "g:civic", "status": "no_decision",
            "candidates": ["@alice"], "voter_snapshot": ["@alice"],
            "seats": 5, "start_height": 1, "end_height": 8,
            "finalized_at_height": 9, "created_at_height": 2, "winners": [],
        },
        "e:finished": {
            "election_id": "e:finished", "group_id": "g:civic", "status": "finalized",
            "candidates": ["@bob", "@alice"], "voter_snapshot": ["@alice"],
            "seats": 5, "start_height": 1, "end_height": 5,
            "finalized_at_height": 6, "created_at_height": 1, "winners": ["@alice"],
        },
        "e:other": {
            "election_id": "e:other", "group_id": "g:other", "status": "open",
            "candidates": ["@bob"], "voter_snapshot": ["@bob"],
        },
    }
    state["group_emissary_ballots"] = {"e:open": {"@alice": {"ranking": ["@bob"]}}}
    state["group_emissary_ballot_nullifiers"] = {"e:open": {"private": "never_publish"}}
    return state


def test_group_election_index_is_allowlisted_public_scoped_and_paginated() -> None:
    from copy import deepcopy
    state = _election_state()
    original = deepcopy(state)
    with _client(state) as client:
        first = client.get("/v1/groups/g:civic/elections?limit=2")
        second = client.get("/v1/groups/g:civic/elections?limit=2&offset=2")
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["ok"] is True
    assert body["read_only"] is True
    assert body["total"] == 3
    assert body["observed_height"] == 12
    assert [row["election_id"] for row in body["items"]] == ["e:open", "e:empty"]
    assert body["next_offset"] == 2
    assert [row["election_id"] for row in second.json()["items"]] == ["e:finished"]
    assert second.json()["next_offset"] is None
    assert body["items"][0]["candidates"] == ["@alice", "@bob"]
    assert body["items"][0]["voter_snapshot_count"] == 1
    assert body["items"][0]["viewer_in_voter_snapshot"] is None
    assert body["items"][0]["ballot_submission_authorized"] is False
    serialized = str(body) + str(second.json())
    for forbidden in ("never_publish", "nullifiers", "ranking", "ballots", "voter_snapshot':"):
        assert forbidden not in serialized
    assert state == original


def test_group_election_detail_exact_scope_and_completed_outcomes() -> None:
    with _client(_election_state()) as client:
        finished = client.get("/v1/groups/g:civic/elections/e:finished")
        empty = client.get("/v1/groups/g:civic/elections/e:empty")
        wrong_scope = client.get("/v1/groups/g:civic/elections/e:other")
        unknown = client.get("/v1/groups/g:civic/elections/unknown")
        missing_group = client.get("/v1/groups/absent/elections")
    assert finished.status_code == 200
    assert finished.json()["election"]["winners"] == ["@alice"]
    assert finished.json()["election"]["outcome_recorded"] is True
    assert finished.json()["election"]["finalized_at_height"] == 6
    assert empty.status_code == 200
    assert empty.json()["election"]["status"] == "no_decision"
    assert empty.json()["election"]["winners"] == []
    assert wrong_scope.status_code == 404
    assert unknown.status_code == 404
    assert missing_group.status_code == 404


def test_group_election_self_snapshot_requires_active_session() -> None:
    with _client(_election_state()) as client:
        anonymous = client.get("/v1/groups/g:civic/elections/e:open?account=@alice")
        forged = client.get("/v1/groups/g:civic/elections/e:open", headers={
            "x-weall-account": "@alice", "x-weall-session-key": "invalid",
        })
        valid = client.get("/v1/groups/g:civic/elections/e:open", headers={
            "x-weall-account": "@alice", "x-weall-session-key": "alice-session",
        })
    assert anonymous.json()["election"]["viewer_in_voter_snapshot"] is None
    assert forged.json()["election"]["viewer_in_voter_snapshot"] is None
    assert valid.status_code == 200
    assert valid.json()["election"]["viewer_in_voter_snapshot"] is True
