from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app

CID = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"


class _FakeExecutor:
    def __init__(self, state: dict) -> None:
        self._state = state

    def read_state(self) -> dict:
        return self._state

    def snapshot(self) -> dict:
        return self._state

    def tx_index_hash(self) -> str:
        return "batch356-tx-index"


def _client(state: dict) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def _auth(account: str) -> dict[str, str]:
    return {"x-weall-account": account, "x-weall-session-key": f"sk:{account}"}


def _state() -> dict:
    return {
        "chain_id": "batch356",
        "time": 1_700_000_000,
        "accounts": {
            acct: {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "session_keys": {f"sk:{acct}": {"active": True, "ttl_s": 0}},
            }
            for acct in ("@alice", "@bob", "@carol")
        },
        "messaging": {
            "threads_by_id": {
                "dm:@alice:@bob": {
                    "thread_id": "dm:@alice:@bob",
                    "members": ["@alice", "@bob"],
                    "created_at_nonce": 1,
                    "last_message_at_nonce": 2,
                    "last_message_id": "dm:2",
                    "message_ids": ["dm:1", "dm:2"],
                },
                "dm:@bob:@carol": {
                    "thread_id": "dm:@bob:@carol",
                    "members": ["@bob", "@carol"],
                    "created_at_nonce": 3,
                    "last_message_at_nonce": 3,
                    "last_message_id": "dm:3",
                    "message_ids": ["dm:3"],
                },
            },
            "messages_by_id": {
                "dm:1": {"message_id": "dm:1", "thread_id": "dm:@alice:@bob", "sender": "@alice", "to": "@bob", "body": "hello bob", "created_at_nonce": 1},
                "dm:2": {"message_id": "dm:2", "thread_id": "dm:@alice:@bob", "sender": "@bob", "to": "@alice", "body": "hello alice", "created_at_nonce": 2},
                "dm:3": {"message_id": "dm:3", "thread_id": "dm:@bob:@carol", "sender": "@bob", "to": "@carol", "body": "private carol", "created_at_nonce": 3},
            },
            "inbox_by_account": {
                "@alice": {"threads": ["dm:@alice:@bob"], "messages": ["dm:1", "dm:2"]},
                "@bob": {"threads": ["dm:@alice:@bob", "dm:@bob:@carol"], "messages": ["dm:1", "dm:2", "dm:3"]},
                "@carol": {"threads": ["dm:@bob:@carol"], "messages": ["dm:3"]},
            },
        },
        "content": {
            "posts": {
                "post:1": {"post_id": "post:1", "author": "@alice", "body": "root", "visibility": "public", "media": ["media:1"], "created_nonce": 10, "created_at_nonce": 10}
            },
            "comments": {
                f"comment:{i}": {"comment_id": f"comment:{i}", "post_id": "post:1", "author": "@bob", "body": f"comment {i}", "media": ["media:1"] if i == 1 else [], "created_nonce": i, "created_at_nonce": i}
                for i in range(1, 5)
            },
            "media": {
                "media:1": {"media_id": "media:1", "payload": {"cid": CID, "mime": "image/png", "name": "demo.png", "size_bytes": 1234}}
            },
            "reactions": {},
        },
    }


def test_public_snapshot_redacts_removed_communication_tree_batch356() -> None:
    client = _client(_state())

    res = client.get("/v1/state/snapshot")
    assert res.status_code == 200, res.text
    state = res.json()["state"]
    assert state["messaging"]["redacted"] is True
    assert state["messaging"]["summary"] == {"threads": 2, "messages": 3, "inboxes": 3}
    assert "hello bob" not in res.text
    assert "private carol" not in res.text
    assert "messages_by_id" not in state["messaging"]


def test_removed_message_thread_routes_are_unmounted_batch356() -> None:
    client = _client(_state())

    for path in ["/v1/" + "mess" + "ages/threads", "/v1/" + "mess" + "ages/threads?limit=10"]:
        res = client.get(path, headers=_auth("@alice"))
        assert res.status_code == 404, res.text
        assert "private carol" not in res.text


def test_removed_message_thread_detail_route_is_unmounted_batch356() -> None:
    client = _client(_state())

    for account in ["@alice", "@carol"]:
        res = client.get("/v1/" + "mess" + "ages/threads/dm:@alice:@bob", headers=_auth(account))
        assert res.status_code == 404, res.text


def test_content_and_thread_return_media_summaries_with_paginated_comments_batch356() -> None:
    client = _client(_state())

    content = client.get("/v1/content/post:1")
    assert content.status_code == 200, content.text
    media = content.json()["content"]["media"][0]
    assert media["load_policy"] == "viewport"
    assert media["fetch_path"] == f"/v1/media/proxy/{CID}"

    thread = client.get("/v1/thread/post:1?limit=2")
    assert thread.status_code == 200, thread.text
    body = thread.json()
    assert len(body["comments"]) == 2
    assert body["next_cursor"]
    comment_with_media = client.get("/v1/thread/post:1?limit=4").json()["comments"][-1]
    assert comment_with_media["media"][0]["fetch_path"] == f"/v1/media/proxy/{CID}"


def test_frontend_uses_scoped_read_paths_not_state_snapshot_batch356() -> None:
    root = Path(__file__).resolve().parents[2]
    web = root / "web" / "src"
    review = (web / "pages" / "DisputeReview.tsx").read_text(encoding="utf-8")
    api = (web / "api" / "weall.ts").read_text(encoding="utf-8")

    assert not (web / "pages" / "Messaging.tsx").exists()
    assert "weall.stateSnapshot(apiBase).catch" not in review
    assert "contentMedia = asArray(contentObj?.media)" in review
    assert "/v1/activity/inbox" in api
    assert "/v1/" + "mess" + "ages/threads" not in api
