from __future__ import annotations

from weall.runtime.reputation_accrual import pending_content_accrual, schedule_reputation_accrual_system_txs


def test_reputation_accrual_scheduler_emits_integer_milli_units() -> None:
    state = {
        "height": 8,
        "content": {
            "posts": {
                "post-1": {
                    "visibility": "public",
                    "reputation_accrual": pending_content_accrual(
                        kind="post",
                        source_id="post-1",
                        account_id="@alice",
                        created_height=0,
                        delta_milli=10,
                        maturity_blocks=8,
                    ),
                }
            },
            "flags": {},
        },
    }

    assert schedule_reputation_accrual_system_txs(state, next_height=9) == 1
    queue = state.get("system_tx_queue") or state.get("system_txs") or []
    assert queue
    item = queue[0]
    payload = item.get("payload") if isinstance(item, dict) else None
    assert isinstance(payload, dict)
    assert payload.get("delta_milli") == 10
    assert isinstance(payload.get("delta_milli"), int)
    assert "delta" not in payload
