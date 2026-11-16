"""A03 non-authoritative incremental SQL delta and two-node replay evidence."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from weall.api.public_lobby_incremental_candidate import (
    PublicLobbyIncrementalCandidate,
    prepare_comment_delta,
)
from weall.api.public_lobby_index_candidate import (
    PublicLobbyIndexCandidate,
    PublicLobbyIndexUnavailable,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root


def _state() -> dict:
    return {
        "height": 1,
        "tip": "block-1",
        "content": {
            "comments": {
                "c1": {
                    "comment_id": "c1",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "author": "@alpha",
                    "body": "hello",
                    "created_nonce": 2,
                    "visibility": "public",
                },
                "c2": {
                    "comment_id": "c2",
                    "post_id": "public-lobby:welcome",
                    "surface": "public_lobby",
                    "author": "@beta",
                    "body": "hidden",
                    "created_nonce": 3,
                    "visibility": "private",
                },
            },
            "moderation": {"targets": {}},
        },
        "disputes_by_id": {},
        "disputes_by_target": {},
    }


def test_incremental_row_delta_correctly_changes_and_drops_visibility() -> None:
    old = _state()
    new = deepcopy(old)
    comments = new["content"]["comments"]
    comments["c1"]["post_id"] = "public-lobby:other"
    comments["c1"]["body"] = "moved"
    comments["c2"]["visibility"] = "public"
    comments["c3"] = {
        "comment_id": "c3",
        "post_id": "public-lobby:welcome",
        "surface": "public_lobby",
        "author": "@gamma",
        "body": "new",
        "created_nonce": 4,
    }
    changed, rows = prepare_comment_delta(old, new)
    assert changed == ["c1", "c2", "c3"]
    assert [(r[0], r[1], r[4]) for r in rows] == [
        ("public-lobby:other", "c1", "moved"),
        ("public-lobby:welcome", "c2", "hidden"),
        ("public-lobby:welcome", "c3", "new"),
    ]
    newer = deepcopy(new)
    newer["content"]["comments"]["c2"]["deleted"] = True
    changed, rows = prepare_comment_delta(new, newer)
    assert changed == ["c2"] and rows == []


def test_incremental_delta_refuses_moderation_dispute_and_too_many_changes() -> None:
    old = _state()
    for mutation, error in (
        (
            lambda s: s["content"]["moderation"]["targets"].update({"c1": {"deleted": True}}),
            "content_policy_change_requires_full_rebuild",
        ),
        (
            lambda s: s["disputes_by_id"].update({"d1": {"target_id": "c1"}}),
            "dispute_change_requires_full_rebuild",
        ),
        (
            lambda s: s["disputes_by_target"].update({"content:c1": "d1"}),
            "dispute_change_requires_full_rebuild",
        ),
    ):
        new = deepcopy(old)
        mutation(new)
        with pytest.raises(PublicLobbyIndexUnavailable, match=error):
            prepare_comment_delta(old, new)

    many = deepcopy(old)
    for i in range(257):
        many["content"]["comments"][f"bulk-{i:05d}"] = {
            "comment_id": f"bulk-{i:05d}",
            "post_id": "public-lobby:welcome",
            "surface": "public_lobby",
        }
    with pytest.raises(PublicLobbyIndexUnavailable, match="delta_change_budget_exceeded"):
        prepare_comment_delta(old, many)


def _executor(tmp_path: Path, name: str, monkeypatch: pytest.MonkeyPatch) -> WeAllExecutor:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.sqlite"),
        node_id=name,
        chain_id="pr93-a03-two-node-local-delta",
        tx_index_path=str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"),
    )


def _arm(
    executor: WeAllExecutor,
) -> tuple[PublicLobbyIndexCandidate, PublicLobbyIncrementalCandidate]:
    index = PublicLobbyIndexCandidate(executor._db)
    index.initialize()
    index.attach_commit_invalidation()
    index.rebuild_from_local_ledger(chain_id=executor.chain_id)
    delta = PublicLobbyIncrementalCandidate(index)
    delta.arm_after_verified_rebuild(chain_id=executor.chain_id)
    return index, delta


def test_real_producer_follower_replay_delta_restart_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer = _executor(tmp_path, "producer", monkeypatch)
    follower = _executor(tmp_path, "follower", monkeypatch)
    first = producer.produce_block(max_txs=0, allow_empty=True)
    assert first.ok, first.error
    m1 = follower.apply_block(producer.get_block_by_height(1))
    assert m1.ok, m1.error

    producer_index, producer_delta = _arm(producer)
    follower_index, follower_delta = _arm(follower)
    before_p = deepcopy(producer.read_state())
    before_f = deepcopy(follower.read_state())
    assert compute_state_root(before_p) == compute_state_root(before_f)

    second = producer.produce_block(max_txs=0, allow_empty=True)
    assert second.ok, second.error
    m2 = follower.apply_block(producer.get_block_by_height(2))
    assert m2.ok, m2.error
    for idx, ex in ((producer_index, producer), (follower_index, follower)):
        with pytest.raises(PublicLobbyIndexUnavailable, match="stale"):
            idx.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id=ex.chain_id)
    updated_p = producer_delta.advance_one_committed_block(
        previous_state=before_p, chain_id=producer.chain_id
    )
    updated_f = follower_delta.advance_one_committed_block(
        previous_state=before_f, chain_id=follower.chain_id
    )
    assert updated_p == updated_f == 0
    first_page = producer_index.page_from_local_ledger(
        thread_id="public-lobby:welcome", chain_id=producer.chain_id
    )
    second_page = follower_index.page_from_local_ledger(
        thread_id="public-lobby:welcome", chain_id=follower.chain_id
    )
    assert first_page == second_page
    assert first_page["items"] == []

    restarted = _executor(tmp_path, "follower", monkeypatch)
    persisted = PublicLobbyIndexCandidate(restarted._db)
    # Startup's legitimate same-height local BFT/metadata persistence also
    # changes ledger_state; the durable trigger MUST invalidate the index.
    with pytest.raises(PublicLobbyIndexUnavailable, match="stale"):
        persisted.page_from_local_ledger(
            thread_id="public-lobby:welcome", chain_id=restarted.chain_id
        )
    persisted.rebuild_from_local_ledger(chain_id=restarted.chain_id)
    PublicLobbyIncrementalCandidate(persisted).arm_after_verified_rebuild(
        chain_id=restarted.chain_id
    )
    restored_page = persisted.page_from_local_ledger(
        thread_id="public-lobby:welcome", chain_id=restarted.chain_id
    )
    assert restored_page == first_page
    assert restarted.read_state()["height"] == 2


def test_real_chain_gap_and_wrong_parent_state_cannot_publish_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer = _executor(tmp_path, "gap-producer", monkeypatch)
    assert producer.produce_block(max_txs=0, allow_empty=True).ok
    index, incremental = _arm(producer)
    before = deepcopy(producer.read_state())
    altered = deepcopy(before)
    altered["forged_noncontent"] = {"not_in_previous_committed_root": True}
    assert producer.produce_block(max_txs=0, allow_empty=True).ok

    with pytest.raises(PublicLobbyIndexUnavailable, match="parent_shadow_anchor_mismatch"):
        incremental.advance_one_committed_block(previous_state=altered, chain_id=producer.chain_id)
    with pytest.raises(PublicLobbyIndexUnavailable, match="stale"):
        index.page_from_local_ledger(thread_id="public-lobby:welcome", chain_id=producer.chain_id)
    assert producer.produce_block(max_txs=0, allow_empty=True).ok
    with pytest.raises(PublicLobbyIndexUnavailable, match="single_block_delta_required"):
        incremental.advance_one_committed_block(previous_state=before, chain_id=producer.chain_id)
