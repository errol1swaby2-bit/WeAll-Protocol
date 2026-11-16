"""PR93 A03: shadow index proof is durable but has NO production authority."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api import public_lobby_index_candidate as candidate
from weall.runtime.sqlite_db import SqliteDB
from weall.runtime.state_hash import compute_state_root


class _FixtureExecutor:
    def __init__(self, state: dict) -> None:
        self.state = state

    def read_state(self) -> dict:
        return self.state


def _state() -> dict:
    return {
        "chain_id": "shadow-test-chain",
        "height": 2,
        "tip": "block-2",
        "content": {
            "comments": {
                "a": {
                    "comment_id": "a",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "created_nonce": 5,
                    "author": "@alpha",
                    "body": "one",
                    "visibility": "public",
                },
                "b": {
                    "comment_id": "b",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "created_nonce": 5,
                    "author": "@beta",
                    "body": "two",
                    "visibility": "public",
                },
                "hidden": {
                    "comment_id": "hidden",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "created_nonce": 99,
                    "author": "@bad",
                    "body": "no",
                },
                "other": {
                    "comment_id": "other",
                    "post_id": "public-lobby:other",
                    "surface": "public_lobby",
                    "created_nonce": 11,
                    "author": "@other",
                    "body": "elsewhere",
                },
                "spoof": {
                    "id": "spoof-alias",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "created_nonce": 100,
                },
                "ordinary": {
                    "comment_id": "ordinary",
                    "post_id": "ordinary-post",
                    "surface": "comment",
                    "created_nonce": 101,
                },
            },
            "moderation": {"targets": {"hidden": {"last_action": "hide"}}},
        },
    }


def _binding(state: dict) -> dict:
    return {
        "chain_id": "shadow-test-chain",
        "height": state["height"],
        "block_id": state["tip"],
        "state_root": compute_state_root(state),
    }


def _client(state: dict) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FixtureExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _index(tmp_path) -> candidate.PublicLobbyIndexCandidate:
    index = candidate.PublicLobbyIndexCandidate(
        SqliteDB(path=str(tmp_path / "lobby-shadow.sqlite"))
    )
    index.initialize()
    return index


def test_shadow_pages_match_canonical_anonymous_route_across_equal_nonce_and_threads(
    tmp_path,
) -> None:
    state = _state()
    binding = _binding(state)
    client = _client(state)
    index = _index(tmp_path)
    assert index.rebuild(state=state, **binding) == 3

    for thread in ("public-lobby:welcome", "public-lobby:other", "public-lobby:empty"):
        cursor = ""
        for _ in range(4):
            params = {"thread_id": thread, "limit": 1}
            if cursor:
                params["cursor"] = cursor
            direct = client.get("/v1/public-lobby/comments", params=params)
            assert direct.status_code == 200, direct.text
            shadow = index.page(thread_id=thread, limit=1, cursor=cursor, **binding)
            assert shadow == direct.json()
            cursor = shadow["next_cursor"] or ""
            if not cursor:
                break
        else:
            pytest.fail("unexpected nonterminating public lobby cursor")


def test_shadow_rebuild_reflects_committed_dispute_moderation_and_restart(tmp_path) -> None:
    state = _state()
    binding = _binding(state)
    index = _index(tmp_path)
    index.rebuild(state=state, **binding)

    updated = deepcopy(state)
    updated["height"] = 3
    updated["tip"] = "block-3"
    updated["disputes_by_id"] = {
        "dispute-b": {
            "target_type": "comment",
            "target_id": "b",
            "stage": "appeal",
            "resolution": {"outcome": "remove"},
        }
    }
    updated_binding = _binding(updated)

    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="stale"):
        index.page(thread_id="public-lobby:welcome", **updated_binding)

    assert index.rebuild(state=updated, **updated_binding) == 2

    # A new process can open the derivative DB, without touching global
    # state_json, and sees the exact new moderation-suppressed page.
    reopened = candidate.PublicLobbyIndexCandidate(
        SqliteDB(path=str(tmp_path / "lobby-shadow.sqlite"))
    )
    direct = _client(updated).get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:welcome"},
    )
    assert direct.status_code == 200, direct.text
    assert reopened.page(thread_id="public-lobby:welcome", **updated_binding) == direct.json()


def test_shadow_rejects_stale_forged_or_same_height_conflicting_binding(tmp_path) -> None:
    state = _state()
    binding = _binding(state)
    index = _index(tmp_path)
    index.rebuild(state=state, **binding)
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="stale"):
        index.page(
            thread_id="public-lobby:welcome",
            **{**binding, "state_root": "00" * 32},
        )
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="state_root_mismatch"):
        index.rebuild(
            state=state,
            **{**binding, "state_root": "aa" * 32},
        )
    altered = deepcopy(state)
    altered["content"]["comments"]["new"] = {
        "comment_id": "new",
        "surface": "public_lobby",
        "post_id": "public-lobby:welcome",
        "created_nonce": 6,
    }
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="same_height_binding_conflict"):
        index.rebuild(state=altered, **_binding(altered))
    assert [x["comment_id"] for x in index.page(
        thread_id="public-lobby:welcome", **binding
    )["items"]] == ["b", "a"]


def test_shadow_failure_during_projection_does_not_publish_partial_rows(
    tmp_path, monkeypatch
) -> None:
    state = _state()
    binding = _binding(state)
    index = _index(tmp_path)
    index.rebuild(state=state, **binding)

    updated = deepcopy(state)
    updated["height"] = 3
    updated["tip"] = "block-3"
    updated["content"]["comments"]["new"] = {
        "comment_id": "new",
        "surface": "public_lobby",
        "post_id": "public-lobby:welcome",
        "created_nonce": 6,
    }

    def fail_visibility(*_args, **_kwargs):
        raise RuntimeError("injected projection failure")

    monkeypatch.setattr(candidate, "_comment_visible", fail_visibility)
    with pytest.raises(RuntimeError, match="injected projection failure"):
        index.rebuild(state=updated, **_binding(updated))
    old_page = index.page(thread_id="public-lobby:welcome", **binding)
    assert [item["comment_id"] for item in old_page["items"]] == ["b", "a"]
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="stale"):
        index.page(thread_id="public-lobby:welcome", **_binding(updated))


def test_shadow_rejects_invalid_cursors_and_never_uses_legacy_identity(tmp_path) -> None:
    state = _state()
    binding = _binding(state)
    index = _index(tmp_path)
    index.rebuild(state=state, **binding)
    for cursor in ("invalid", "x" * 4097):
        with pytest.raises(ValueError, match="invalid_cursor"):
            index.page(
                thread_id="public-lobby:welcome",
                cursor=cursor,
                **binding,
            )
    with pytest.raises(ValueError, match="invalid_public_lobby_target"):
        index.page(thread_id="ordinary-post", **binding)


def test_shadow_pagination_can_read_large_thread_without_route_scan(tmp_path) -> None:
    state = _state()
    for n in range(1200):
        cid = "bulk-%05d" % n
        state["content"]["comments"][cid] = {
            "comment_id": cid,
            "post_id": "public-lobby:bulk",
            "surface": "public_lobby",
            "author": "@bulk",
            "body": "content",
            "created_nonce": n + 1,
        }
    binding = _binding(state)
    index = _index(tmp_path)
    index.rebuild(state=state, **binding)
    first = index.page(thread_id="public-lobby:bulk", limit=2, **binding)
    assert [row["comment_id"] for row in first["items"]] == [
        "bulk-01199",
        "bulk-01198",
    ]
    second = index.page(
        thread_id="public-lobby:bulk",
        limit=2,
        cursor=first["next_cursor"],
        **binding,
    )
    assert [row["comment_id"] for row in second["items"]] == [
        "bulk-01197",
        "bulk-01196",
    ]
