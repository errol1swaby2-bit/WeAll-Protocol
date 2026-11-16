"""Bounded public-lobby reads are publicly visible, scoped, and moderated.

This unit fixture exercises only read-model behavior. Real ML-DSA signed
Tier-0 submits and committed receipts are verified by M4.2 Playwright CI.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _StateExecutor:
    def __init__(self, state: dict) -> None:
        self.state = state

    def read_state(self) -> dict:
        return self.state


def _client() -> TestClient:
    state = {
        "content": {
            "posts": {},
            "comments": {
                "c1": {
                    "comment_id": "c1",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "author": "@alpha",
                    "body": "Hello from alpha",
                    "created_nonce": 3,
                    "visibility": "public",
                    "deleted": False,
                },
                "c2": {
                    "comment_id": "c2",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "author": "@beta",
                    "body": "Hello from beta",
                    "created_nonce": 3,
                    "visibility": "public",
                    "deleted": False,
                },
                "c-other": {
                    "comment_id": "c-other",
                    "post_id": "public-lobby:other",
                    "surface": "public_lobby",
                    "author": "@gamma",
                    "body": "Other thread",
                    "created_nonce": 5,
                    "visibility": "public",
                    "deleted": False,
                },
                "c-deleted": {
                    "comment_id": "c-deleted",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "author": "@alpha",
                    "body": "Deleted",
                    "created_nonce": 4,
                    "visibility": "public",
                    "deleted": True,
                },
                "c-hidden": {
                    "comment_id": "c-hidden",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "author": "@beta",
                    "body": "Hidden",
                    "created_nonce": 6,
                    "visibility": "public",
                    "deleted": False,
                },
                "c-private": {
                    "comment_id": "c-private",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "author": "@alpha",
                    "body": "Not public",
                    "created_nonce": 7,
                    "visibility": "private",
                    "deleted": False,
                },
                "c-nonlobby": {
                    "comment_id": "c-nonlobby",
                    "post_id": "public-lobby:welcome",
                    "author": "@beta",
                    "body": "Wrong surface",
                    "created_nonce": 8,
                    "visibility": "public",
                    "deleted": False,
                },
                "c-badtarget": {
                    "comment_id": "c-badtarget",
                    "post_id": "ordinary-post",
                    "surface": "public_lobby",
                    "author": "@beta",
                    "body": "Invalid target",
                    "created_nonce": 9,
                    "visibility": "public",
                    "deleted": False,
                },
            },
            "moderation": {"targets": {"c-hidden": {"last_action": "hide"}}},
        },
    }
    app = create_app(boot_runtime=False)
    app.state.executor = _StateExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def test_anonymous_lobby_comment_read_is_bounded_and_scoped() -> None:
    # Each signer has its own nonce sequence: independent accounts may
    # legitimately create different comments at the same nonce.
    client = _client()
    first = client.get(
        "/v1/public-lobby/comments", params={"thread_id": "public-lobby:welcome", "limit": 1}
    )
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["ok"] is True
    assert body["thread_id"] == "public-lobby:welcome"
    assert [item["comment_id"] for item in body["items"]] == ["c2"]
    assert body["items"][0]["body"] == "Hello from beta"
    assert set(body["items"][0]) == {
        "comment_id",
        "post_id",
        "surface",
        "author",
        "body",
        "created_nonce",
        "visibility",
    }
    assert body["next_cursor"]

    second = client.get(
        "/v1/public-lobby/comments",
        params={
            "thread_id": "public-lobby:welcome",
            "limit": 1,
            "cursor": body["next_cursor"],
        },
    )
    assert second.status_code == 200, second.text
    page = second.json()
    assert [item["comment_id"] for item in page["items"]] == ["c1"]
    assert page["next_cursor"] is None

    other = client.get(
        "/v1/public-lobby/comments",
        params={
            "thread_id": "public-lobby:other",
        },
    )
    assert other.status_code == 200
    assert [item["comment_id"] for item in other.json()["items"]] == ["c-other"]


def test_lobby_comment_detail_and_moderation_are_consistent() -> None:
    client = _client()
    visible = client.get("/v1/content/c1")
    assert visible.status_code == 200
    assert visible.json()["type"] == "comment"
    assert visible.json()["content"]["post_id"] == "public-lobby:welcome"
    for content_id in ("c-hidden", "c-deleted", "c-private", "c-badtarget"):
        response = client.get("/v1/content/" + content_id)
        assert response.status_code == 404, (content_id, response.text)


def test_lobby_reads_fail_closed_on_invalid_scopes_and_cursors() -> None:
    client = _client()
    for thread_id in ("", "ordinary-post", "public-lobb:y", "public-lobby:other" * 300):
        result = client.get(
            "/v1/public-lobby/comments",
            params={
                "thread_id": thread_id,
            },
        )
        assert result.status_code == 400, result.text

    invalid_cursor = client.get(
        "/v1/public-lobby/comments",
        params={
            "thread_id": "public-lobby:welcome",
            "cursor": "not-a-valid-cursor",
        },
    )
    assert invalid_cursor.status_code == 400


def test_malformed_lobby_index_aliases_never_escape_public_list_or_detail() -> None:
    """Legacy aliases must not supply a synthetic public-lobby identity.

    In particular, a moderation entry indexed by the map key must not be
    bypassable by an unbound legacy "id" field on that comment record.
    """
    client = _client()
    content = client.app.state.executor.state["content"]
    comments = content["comments"]
    template = {
        "post_id": "public-lobby:welcome",
        "surface": "public_lobby",
        "author": "@spoof",
        "body": "Should not be returned",
        "created_nonce": 100,
        "visibility": "public",
        "deleted": False,
    }
    comments["c-missing-canonical"] = {
        **template,
        "id": "legacy-alias-not-index",
    }
    comments["c-mismatched-canonical"] = {
        **template,
        "comment_id": "different-index",
    }
    comments["c-hidden-at-index"] = {
        **template,
        "id": "unrelated-legacy-target",
    }
    content["moderation"]["targets"]["c-hidden-at-index"] = {"last_action": "hide"}

    read = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:welcome", "limit": 50},
    )
    assert read.status_code == 200, read.text
    assert {row["comment_id"] for row in read.json()["items"]} == {"c1", "c2"}
    for indexed_id in (
        "c-missing-canonical",
        "c-mismatched-canonical",
        "c-hidden-at-index",
    ):
        detail = client.get("/v1/content/" + indexed_id)
        assert detail.status_code == 404, (indexed_id, detail.text)


def test_public_lobby_state_unavailable_is_not_a_false_empty_success() -> None:
    """A temporarily missing, malformed or failing chain snapshot must be 503."""
    client = _client()
    original = client.app.state.executor

    class _ReadFailure:
        def read_state(self) -> dict:
            raise RuntimeError("sensitive backend error")

    class _MalformedState:
        def read_state(self) -> list:
            return []

    for unavailable in (None, object(), _ReadFailure(), _MalformedState()):
        client.app.state.executor = unavailable
        response = client.get(
            "/v1/public-lobby/comments",
            params={"thread_id": "public-lobby:welcome"},
        )
        assert response.status_code == 503, response.text
        error = response.json()
        assert error["ok"] is False
        assert error["error"]["code"] == "public_lobby_state_unavailable"
        assert "sensitive backend error" not in response.text

    client.app.state.executor = original
    healthy = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:welcome"},
    )
    assert healthy.status_code == 200
    assert {row["comment_id"] for row in healthy.json()["items"]} == {"c1", "c2"}

    original.state["content"]["comments"] = {}
    genuinely_empty = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:welcome"},
    )
    assert genuinely_empty.status_code == 200
    assert genuinely_empty.json()["items"] == []


def test_public_lobby_large_eligible_thread_only_evaluates_the_requested_window(
    monkeypatch,
) -> None:
    """Apply expensive moderation checks only through the next visible page."""
    from weall.api.routes_public_parts import content as routes

    client = _client()
    comments = client.app.state.executor.state["content"]["comments"]
    for n in range(1800):
        key = f"sample-{n:05d}"
        comments[key] = {
            "comment_id": key,
            "post_id": "public-lobby:bulk",
            "surface": "public_lobby",
            "author": "@bulk",
            "body": "same body",
            "created_nonce": n + 1,
            "visibility": "public",
        }

    evaluations = []
    original = routes._comment_visible

    def instrumented(state, comment, comment_id=""):
        evaluations.append(comment_id)
        return original(state, comment, comment_id)

    monkeypatch.setattr(routes, "_comment_visible", instrumented)
    result = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:bulk", "limit": 2},
    )
    assert result.status_code == 200, result.text
    assert [row["comment_id"] for row in result.json()["items"]] == [
        "sample-01799",
        "sample-01798",
    ]
    assert evaluations == ["sample-01799", "sample-01798", "sample-01797"]
    assert result.json()["next_cursor"]


def test_public_lobby_rejects_global_scan_over_budget_instead_of_lying() -> None:
    from weall.api.routes_public_parts import content as routes

    client = _client()
    comments = client.app.state.executor.state["content"]["comments"]
    for n in range(routes._PUBLIC_LOBBY_MAX_GLOBAL_COMMENTS + 1):
        comments[f"unrelated-{n}"] = {}
    res = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:welcome"},
    )
    assert res.status_code == 503, res.text
    assert res.json()["error"]["code"] == "public_lobby_read_budget_exceeded"


def test_public_lobby_hiding_many_prefix_records_fails_closed_not_partial() -> None:
    from weall.api.routes_public_parts import content as routes

    client = _client()
    state = client.app.state.executor.state
    comments = state["content"]["comments"]
    for n in range(routes._PUBLIC_LOBBY_MAX_VISIBILITY_EVALUATIONS + 1):
        key = f"hidden-{n:05d}"
        comments[key] = {
            "comment_id": key,
            "post_id": "public-lobby:blocked",
            "surface": "public_lobby",
            "author": "@bulk",
            "body": "hidden",
            "created_nonce": n + 2,
            "visibility": "private",
        }
    comments["last-visible"] = {
        "comment_id": "last-visible",
        "post_id": "public-lobby:blocked",
        "surface": "public_lobby",
        "author": "@bulk",
        "body": "visible after hidden prefix",
        "created_nonce": 1,
        "visibility": "public",
    }
    res = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:blocked", "limit": 1},
    )
    assert res.status_code == 503, res.text
    assert res.json()["error"]["code"] == "public_lobby_read_budget_exceeded"


def test_public_lobby_dispute_scan_and_cursor_bytes_have_bounded_limits() -> None:
    from weall.api.routes_public_parts import content as routes

    client = _client()
    state = client.app.state.executor.state
    state["disputes_by_id"] = {
        f"d-{n}": {} for n in range(routes._PUBLIC_LOBBY_MAX_DISPUTES + 1)
    }
    res = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:welcome"},
    )
    assert res.status_code == 503
    assert res.json()["error"]["code"] == "public_lobby_read_budget_exceeded"

    # Reject oversized cursors before attempting to decode or read any state.
    cursor = client.get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:welcome", "cursor": "a" * 4097},
    )
    assert cursor.status_code == 400
    assert cursor.json()["error"]["code"] == "invalid_cursor"
