from __future__ import annotations

from weall.runtime.bft_hotstuff import validator_set_hash


def test_validator_set_hash_changes_deterministically_across_epoch_transition() -> None:
    a = validator_set_hash(["v1", "v2", "v3", "v4"])
    b = validator_set_hash(["v1", "v2", "v3", "v5"])
    c = validator_set_hash(["v5", "v3", "v2", "v1"])
    assert a != b
    assert b == c
