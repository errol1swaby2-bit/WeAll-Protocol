from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    def __init__(self, state: dict) -> None:
        self._state = state

    def read_state(self) -> dict:
        return self._state

    def snapshot(self) -> dict:
        return self._state

    def tx_index_hash(self) -> str:
        return "txindexhash-public-profile"


def _state() -> dict:
    return {
        "chain_id": "weall-public-profile-test",
        "height": 42,
        "time": 1_700_000_123,
        "accounts": {
            "@alice": {
                "nonce": 8,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": 4,
                "session_keys": {
                    "owner-session-secret": {"active": True},
                },
                "devices": {
                    "by_id": {
                        "browser:@alice:private": {
                            "device_type": "browser",
                            "fingerprint": "private-device-fingerprint",
                        }
                    }
                },
            }
        },
        "poh": {
            "identity_evidence": {
                "@alice": {
                    "raw_video": "raw-video-do-not-expose",
                    "government_id": "gov-id-do-not-expose",
                }
            }
        },
        "social": {
            "profiles_by_id": {
                "@alice": {
                    "display_name": "Alice Civic",
                    "bio": "Building public civic tools.",
                    "avatar_cid": "bafy-avatar",
                    "banner_cid": "bafy-banner",
                    "website": "https://example.org",
                    "location": "Public town label",
                    "tags": ["civic", "builder", "civic"],
                    "raw_video": "profile-raw-video-do-not-expose",
                    "government_id": "profile-gov-id-do-not-expose",
                    "private_notes": "profile-private-notes-do-not-expose",
                    "created_at_nonce": 2,
                    "updated_at_nonce": 7,
                }
            },
            "shares_by_id": {
                "share:1": {"by": "@alice", "target_id": "post:1"},
            },
            "follows_by_edge": {
                "@alice:@bob": {"from": "@alice", "to": "@bob", "active": True},
                "@alice:@carol": {"from": "@alice", "to": "@carol", "active": False},
            },
        },
        "content": {
            "posts": {
                "post:1": {"post_id": "post:1", "author": "@alice", "visibility": "public", "created_nonce": 10},
                "post:2": {"post_id": "post:2", "author": "@alice", "visibility": "public", "deleted": True},
                "post:3": {"post_id": "post:3", "author": "@bob", "visibility": "public"},
            },
            "comments": {
                "comment:1": {"comment_id": "comment:1", "author": "@alice", "visibility": "public"},
                "comment:2": {"comment_id": "comment:2", "author": "@alice", "visibility": "private"},
            },
        },
    }


def _client(state: dict) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def test_public_profile_read_model_exposes_public_metadata_and_activity_only() -> None:
    client = _client(_state())

    res = client.get("/v1/accounts/@alice/profile")
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["ok"] is True
    assert body["schema"] == "weall.public_profile.v1"
    assert body["account"] == "@alice"
    assert body["exists"] is True
    assert body["truth_boundary"] == "public_derived_index_view_of_chain_state"
    assert body["privacy_boundary"] == "raw_poh_identity_evidence_device_secrets_and_recovery_material_are_not_exposed"

    profile = body["profile"]
    assert profile == {
        "account_id": "@alice",
        "display_name": "Alice Civic",
        "bio": "Building public civic tools.",
        "avatar_cid": "bafy-avatar",
        "banner_cid": "bafy-banner",
        "website": "https://example.org",
        "location": "Public town label",
        "tags": ["civic", "builder"],
        "created_at_nonce": 2,
        "updated_at_nonce": 7,
        "public_links": [{"label": "Website", "url": "https://example.org"}],
        "avatar_media": {
            "cid": "bafy-avatar",
            "kind": "profile_picture",
            "source": "public_media_reference",
            "load_policy": "viewport",
            "fetch_path": "/v1/media/proxy/bafy-avatar",
        },
        "banner_media": {
            "cid": "bafy-banner",
            "kind": "profile_banner",
            "source": "public_media_reference",
            "load_policy": "viewport",
            "fetch_path": "/v1/media/proxy/bafy-banner",
        },
    }

    assert body["public_activity"] == {
        "posts": 1,
        "comments": 1,
        "reposts": 1,
        "following": 1,
        "favorites": 0,
        "truth_boundary": "public_derived_index_view",
        "deferred": ["favorites_index", "profile_timeline", "pinned_post_mutation"],
    }
    assert body["capabilities"] == {
        "profile_edit_tx_type": "PROFILE_UPDATE",
        "profile_edit_requires_owner_signature": True,
        "can_publish_posts": True,
        "can_comment": True,
    }
    assert body["receipt_paths"] == {"submit": "/v1/tx/submit", "status_template": "/v1/tx/status/{tx_id}"}

    dumped = str(body)
    assert "session_keys" not in dumped
    assert "owner-session-secret" not in dumped
    assert "private-device-fingerprint" not in dumped
    assert "raw-video-do-not-expose" not in dumped
    assert "gov-id-do-not-expose" not in dumped
    assert "profile-raw-video-do-not-expose" not in dumped
    assert "profile-gov-id-do-not-expose" not in dumped
    assert "profile-private-notes-do-not-expose" not in dumped


def test_profile_update_endpoint_returns_public_transaction_skeleton_only() -> None:
    client = _client(_state())

    res = client.post(
        "/v1/accounts/tx/profile-update",
        json={
            "account_id": "@alice",
            "display_name": "Alice Civic",
            "bio": "Public bio",
            "avatar_cid": "bafy-avatar",
            "banner_cid": "bafy-banner",
            "website": "https://example.org",
            "location": "Public town label",
            "tags": ["civic", "builder", "civic"],
            "raw_video": "must-not-appear",
            "government_id": "must-not-appear",
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["ok"] is True
    assert body["truth_boundary"] == "transaction_skeleton_only_sign_and_submit_via_v1_tx_submit"
    assert body["public_notice"] == "Profile metadata is public protocol state after the PROFILE_UPDATE transaction commits."
    assert body["tx"] == {
        "tx_type": "PROFILE_UPDATE",
        "signer_hint": "@alice",
        "parent": None,
        "payload": {
            "display_name": "Alice Civic",
            "bio": "Public bio",
            "avatar_cid": "bafy-avatar",
            "banner_cid": "bafy-banner",
            "website": "https://example.org",
            "location": "Public town label",
            "tags": ["civic", "builder"],
        },
    }
    assert "must-not-appear" not in str(body)
