from __future__ import annotations

from weall.runtime.apply.content import apply_content
from weall.runtime.reputation_accrual import (
    RETIRED_CONTENT_ACCRUAL_REASON,
    RETIRED_CONTENT_ACCRUAL_STATUS,
    schedule_reputation_accrual_system_txs,
)
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        system=system,
        parent=parent,
    )


def _state() -> dict:
    return {
        "chain_id": "test",
        "height": 10,
        "params": {
            "content_reputation_maturity_blocks": 2,
            "post_reputation_delta_milli": 10,
            "media_reputation_delta_milli": 25,
        },
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation_milli": 0,
            },
            "@bob": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation_milli": 0,
            },
        },
    }


def _queued_reputation_payloads(state: dict) -> list[dict]:
    return [
        item["payload"]
        for item in state.get("system_queue", [])
        if item.get("tx_type") == "REPUTATION_DELTA_APPLY"
    ]


def _assert_retired(accrual: dict) -> None:
    assert accrual["status"] == RETIRED_CONTENT_ACCRUAL_STATUS
    assert accrual["retired_reason"] == RETIRED_CONTENT_ACCRUAL_REASON


def test_tier2_post_does_not_mature_into_reputation_delta() -> None:
    state = _state()
    apply_content(
        state,
        _env(
            "CONTENT_POST_CREATE",
            "@alice",
            1,
            {"post_id": "post:1", "body": "hello", "visibility": "public"},
        ),
    )

    accrual = state["content"]["posts"]["post:1"]["reputation_accrual"]
    _assert_retired(accrual)

    state["height"] = 12
    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 0
    assert _queued_reputation_payloads(state) == []
    assert state["accounts"]["@alice"]["reputation_milli"] == 0


def test_deleted_or_flagged_content_never_enqueues_reputation() -> None:
    state = _state()
    apply_content(
        state,
        _env("CONTENT_POST_CREATE", "@alice", 1, {"post_id": "post:deleted", "body": "x"}),
    )
    apply_content(
        state,
        _env("CONTENT_POST_DELETE", "@alice", 2, {"post_id": "post:deleted"}),
    )
    apply_content(
        state,
        _env("CONTENT_POST_CREATE", "@alice", 3, {"post_id": "post:flagged", "body": "y"}),
    )
    apply_content(
        state,
        _env(
            "CONTENT_FLAG",
            "@bob",
            1,
            {"target_id": "post:flagged", "flag_id": "flag:1", "reason": "spam"},
        ),
    )

    state["height"] = 12
    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 0
    assert _queued_reputation_payloads(state) == []
    _assert_retired(state["content"]["posts"]["post:deleted"]["reputation_accrual"])
    _assert_retired(state["content"]["posts"]["post:flagged"]["reputation_accrual"])


def test_media_declare_does_not_mature_into_reputation_delta() -> None:
    state = _state()
    apply_content(
        state,
        _env(
            "CONTENT_MEDIA_DECLARE",
            "@alice",
            1,
            {"media_id": "media:1", "cid": "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"},
        ),
    )

    accrual = state["content"]["media"]["media:1"]["reputation_accrual"]
    _assert_retired(accrual)

    state["height"] = 12
    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 0
    assert _queued_reputation_payloads(state) == []
    assert state["accounts"]["@alice"]["reputation_milli"] == 0


def test_legacy_pending_accrual_is_retired_without_emission() -> None:
    state = _state()
    state["content"] = {
        "posts": {
            "post:legacy": {
                "post_id": "post:legacy",
                "author": "@alice",
                "visibility": "public",
                "deleted": False,
                "flags": [],
                "reputation_accrual": {
                    "kind": "post",
                    "source_id": "post:legacy",
                    "account_id": "@alice",
                    "created_height": 1,
                    "matures_at_height": 3,
                    "delta_milli": 10,
                    "status": "pending",
                },
            }
        },
        "media": {},
    }

    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 0
    assert _queued_reputation_payloads(state) == []
    _assert_retired(state["content"]["posts"]["post:legacy"]["reputation_accrual"])

    # Retirement is deterministic and idempotent.
    assert schedule_reputation_accrual_system_txs(state, next_height=14) == 0
    assert _queued_reputation_payloads(state) == []
    _assert_retired(state["content"]["posts"]["post:legacy"]["reputation_accrual"])
