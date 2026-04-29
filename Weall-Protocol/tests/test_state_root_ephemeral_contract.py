from __future__ import annotations

from weall.runtime.state_hash import compute_state_root


def test_state_root_strips_all_consensus_ephemeral_keys() -> None:
    base = {
        "height": 7,
        "accounts": {"@alice": {"nonce": 3, "balance": 9}},
        "finalized": {"height": 6, "block_id": "b6"},
        "params": {"max_block_bytes": 12345},
    }
    with_ephemeral = {
        **base,
        "created_ms": 1_700_000_000_000,
        "bft": {"phase": "prepare", "view": 11},
        "meta": {"schema_version": "1", "operator_note": "local only"},
        "tip_hash": "deadbeef",
        "tip_ts_ms": 1_700_000_000_123,
    }

    assert compute_state_root(with_ephemeral) == compute_state_root(base)


def test_state_root_keeps_non_ephemeral_fields_consensus_binding() -> None:
    left = {
        "height": 7,
        "accounts": {"@alice": {"nonce": 3, "balance": 9}},
        "finalized": {"height": 6, "block_id": "b6"},
        "params": {"max_block_bytes": 12345},
    }
    right = {
        "height": 7,
        "accounts": {"@alice": {"nonce": 4, "balance": 9}},
        "finalized": {"height": 6, "block_id": "b6"},
        "params": {"max_block_bytes": 12345},
    }

    assert compute_state_root(left) != compute_state_root(right)
