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
        "meta": {
            "operator_note": "local only",
            "runtime_open": True,
            "observer_mode": True,
        },
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


def test_state_root_binds_consensus_meta_fields() -> None:
    base = {
        "height": 7,
        "accounts": {"@alice": {"nonce": 3, "balance": 9}},
        "meta": {
            "schema_version": "1",
            "protocol_version": "1.5",
            "recent_block_anchor_activation_height": 10,
        },
    }
    changed = {
        **base,
        "meta": {
            **base["meta"],
            "recent_block_anchor_activation_height": 1,
        },
    }
    assert compute_state_root(base) != compute_state_root(changed)
