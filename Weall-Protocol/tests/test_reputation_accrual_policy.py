from __future__ import annotations

from weall.runtime.apply.content import apply_content
from weall.runtime.apply.reputation import apply_reputation
from weall.runtime.reputation_accrual import schedule_reputation_accrual_system_txs
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


def test_tier2_post_matures_into_system_reputation_delta() -> None:
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

    assert schedule_reputation_accrual_system_txs(state, next_height=11) == 0
    state["height"] = 12
    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 1

    payload = _queued_reputation_payloads(state)[0]
    assert payload == {
        "account_id": "@alice",
        "delta": 0.01,
        "delta_id": "repaccrual:post:post:1",
        "reason": "content_post_matured",
    }

    apply_reputation(
        state,
        _env(
            "REPUTATION_DELTA_APPLY",
            "SYSTEM",
            2,
            payload,
            system=True,
            parent="repaccrual:post:post:1",
        ),
    )
    assert state["accounts"]["@alice"]["reputation_milli"] == 10


def test_deleted_or_flagged_content_does_not_accrue_reputation() -> None:
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
    assert state["content"]["posts"]["post:deleted"]["reputation_accrual"]["status"] == "blocked"
    assert state["content"]["posts"]["post:flagged"]["reputation_accrual"]["status"] == "blocked"


def test_media_declare_matures_into_capped_system_reputation_delta() -> None:
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

    state["height"] = 12
    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 1
    payload = _queued_reputation_payloads(state)[0]
    assert payload["account_id"] == "@alice"
    assert payload["delta"] == 0.025
    assert payload["delta_id"] == "repaccrual:media:media:1"
    assert payload["reason"] == "content_media_matured"
