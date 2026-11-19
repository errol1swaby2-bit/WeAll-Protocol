"""PR93 A03: shadow index proof is durable but has NO production authority."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from weall.api import public_lobby_index_candidate as candidate
from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor
from weall.runtime.sqlite_db import SqliteDB, _canon_json
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
    assert [
        x["comment_id"] for x in index.page(thread_id="public-lobby:welcome", **binding)["items"]
    ] == ["b", "a"]


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
        cid = f"bulk-{n:05d}"
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


def test_shadow_handles_beyond_route_global_and_hidden_prefix_budgets(tmp_path) -> None:
    """Offline projection demonstrates what the route's interim 503 caps forbid."""
    state = _state()
    for n in range(10001):
        state["content"]["comments"][f"unrelated-{n:05d}"] = {"surface": "ordinary"}
    for n in range(520):
        cid = f"private-{n:05d}"
        state["content"]["comments"][cid] = {
            "comment_id": cid,
            "post_id": "public-lobby:deep",
            "surface": "public_lobby",
            "visibility": "private",
            "created_nonce": n + 2,
        }
    state["content"]["comments"]["deep-visible"] = {
        "comment_id": "deep-visible",
        "post_id": "public-lobby:deep",
        "surface": "public_lobby",
        "created_nonce": 1,
        "body": "deeply paginated visible",
    }
    direct = _client(state).get(
        "/v1/public-lobby/comments",
        params={"thread_id": "public-lobby:deep", "limit": 1},
    )
    assert direct.status_code == 503
    assert direct.json()["error"]["code"] == "public_lobby_read_budget_exceeded"

    index = _index(tmp_path)
    binding = _binding(state)
    index.rebuild(state=state, **binding)
    shadow = index.page(thread_id="public-lobby:deep", limit=1, **binding)
    assert [row["comment_id"] for row in shadow["items"]] == ["deep-visible"]
    assert shadow["next_cursor"] is None


def _real_executor(db_path: Path, monkeypatch: pytest.MonkeyPatch) -> WeAllExecutor:
    # Explicit non-BFT, non-genesis rehearsal only. Never disable a production
    # authority check to obtain the shadow-index proof.
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    return WeAllExecutor(
        db_path=str(db_path),
        node_id="shadow-operator",
        chain_id="a03-shadow-ledger-test",
        tx_index_path=str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"),
    )


def test_commit_invalidation_production_block_path_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "real-ledger.sqlite"
    executor = _real_executor(db_path, monkeypatch)
    first = executor.produce_block(max_txs=0, allow_empty=True)
    assert first.ok, first.error

    index = candidate.PublicLobbyIndexCandidate(executor._db)
    index.initialize()
    index.attach_commit_invalidation()
    index.rebuild_from_local_ledger(chain_id=executor.chain_id)
    page = index.page_from_local_ledger(
        thread_id="public-lobby:welcome", chain_id=executor.chain_id
    )
    assert page["items"] == []

    committed = executor.produce_block(max_txs=0, allow_empty=True)
    assert committed.ok, committed.error
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="stale"):
        index.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id=executor.chain_id)

    # Index tables and invalidation triggers survive reopening the real ledger.
    restarted = _real_executor(db_path, monkeypatch)
    after_restart = candidate.PublicLobbyIndexCandidate(restarted._db)
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="stale"):
        after_restart.page_from_local_ledger(
            thread_id="public-lobby:welcome", chain_id=restarted.chain_id
        )
    after_restart.rebuild_from_local_ledger(chain_id=restarted.chain_id)
    page = after_restart.page_from_local_ledger(
        thread_id="public-lobby:welcome", chain_id=restarted.chain_id
    )
    assert page["items"] == []
    assert restarted.read_state()["height"] == 2


def test_commit_trigger_rollback_keeps_prior_index_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = _real_executor(tmp_path / "rollback.sqlite", monkeypatch)
    assert executor.produce_block(max_txs=0, allow_empty=True).ok
    index = candidate.PublicLobbyIndexCandidate(executor._db)
    index.initialize()
    index.attach_commit_invalidation()
    index.rebuild_from_local_ledger(chain_id=executor.chain_id)
    block, state, applied, invalid, error = executor.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert error == ""
    assert block is not None
    assert state is not None
    # Fail after block insertion while the ledger writer transaction remains
    # pending. No trigger-invalidation metadata should commit.
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", "1")
    failed = executor.commit_block_candidate(
        block=block, new_state=state, applied_ids=applied, invalid_ids=invalid
    )
    assert not failed.ok
    page = index.page_from_local_ledger(
        thread_id="public-lobby:welcome", chain_id=executor.chain_id
    )
    assert page["items"] == []
    assert executor.read_state()["height"] == 1


def test_checkpoint_import_invalidates_in_same_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _real_executor(tmp_path / "source.sqlite", monkeypatch)
    for _ in range(3):
        assert source.produce_block(max_txs=0, allow_empty=True).ok
    checkpoint = source.get_block_by_height(3)
    assert checkpoint is not None

    target = _real_executor(tmp_path / "target.sqlite", monkeypatch)
    assert target.produce_block(max_txs=0, allow_empty=True).ok
    index = candidate.PublicLobbyIndexCandidate(target._db)
    index.initialize()
    index.attach_commit_invalidation()
    index.rebuild_from_local_ledger(chain_id=target.chain_id)
    page = index.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id=target.chain_id)
    assert page["items"] == []

    # Storage-layer checkpoint primitive is real; the caller's authenticated
    # state-sync verification, independent finality, and network are NOT tested.
    target._ledger_store.install_state_sync_checkpoint(
        state=source.read_state(), checkpoint_block=checkpoint
    )
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="stale"):
        index.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id=target.chain_id)
    index.rebuild_from_local_ledger(chain_id=target.chain_id)
    page = index.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id=target.chain_id)
    assert page["items"] == []


def test_shadow_cannot_claim_local_committed_binding_without_attached_triggers(
    tmp_path: Path,
) -> None:
    index = _index(tmp_path)
    state = _state()
    index.rebuild(state=state, **_binding(state))
    with pytest.raises(candidate.PublicLobbyIndexUnavailable):
        index.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id="shadow-test-chain")
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="local_ledger_table"):
        index.attach_commit_invalidation()


def test_attached_index_rejects_unverified_rebuild_and_forged_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = _real_executor(tmp_path / "forged.sqlite", monkeypatch)
    assert executor.produce_block(max_txs=0, allow_empty=True).ok
    index = candidate.PublicLobbyIndexCandidate(executor._db)
    index.initialize()
    index.attach_commit_invalidation()
    state = executor.read_state()
    with pytest.raises(
        candidate.PublicLobbyIndexUnavailable, match="attached_index_requires_verified_rebuild"
    ):
        index.rebuild(
            state=state,
            chain_id=executor.chain_id,
            height=int(state["height"]),
            block_id=str(state["tip"]),
            state_root=compute_state_root(state),
        )
    index.rebuild_from_local_ledger(chain_id=executor.chain_id)
    page = index.page_from_local_ledger(
        thread_id="public-lobby:welcome", chain_id=executor.chain_id
    )
    assert page["items"] == []

    # Simulate direct local storage corruption (not a legal state transition).
    # The ledger row can retain its old height and block ID; the committed
    # tip block's cryptographic state-root commitment must still reject it.
    forged = deepcopy(state)
    forged.setdefault("content", {}).setdefault("comments", {})["forged"] = {
        "comment_id": "forged",
        "post_id": "public-lobby:welcome",
        "surface": "public_lobby",
        "created_nonce": 100,
        "body": "not in committed state",
    }
    with executor._db.write_tx() as con:
        con.execute(
            "UPDATE ledger_state SET state_json=? WHERE id=1;",
            (_canon_json(forged),),
        )
    with pytest.raises(
        candidate.PublicLobbyIndexUnavailable, match="committed_tip_state_root_mismatch"
    ):
        index.rebuild_from_local_ledger(chain_id=executor.chain_id)
    with pytest.raises(candidate.PublicLobbyIndexUnavailable, match="stale"):
        index.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id=executor.chain_id)
