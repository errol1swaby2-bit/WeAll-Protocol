from __future__ import annotations

from weall.runtime.bft_hotstuff import validator_set_hash
from weall.runtime.block_admission import _current_validator_set_hash_from_state, _validator_set_hash_from_validators



def test_block_admission_validator_set_hash_matches_canonical_hotstuff_hash() -> None:
    validators = ["v3", "v1", "v2", "v1"]
    assert _validator_set_hash_from_validators(validators) == validator_set_hash(validators)



def test_block_admission_fallback_set_hash_matches_canonical_hash_when_state_has_no_persisted_set_hash() -> None:
    state = {
        "roles": {"validators": {"active_set": ["v4", "v2", "v3", "v2", "v1"]}},
        "consensus": {"validator_set": {"epoch": 9, "active_set": ["v4", "v2", "v3", "v2", "v1"]}},
    }
    assert _current_validator_set_hash_from_state(state) == validator_set_hash(["v1", "v2", "v3", "v4"])



def test_block_admission_prefers_persisted_set_hash_when_present() -> None:
    state = {
        "roles": {"validators": {"active_set": ["v1", "v2", "v3", "v4"]}},
        "consensus": {"validator_set": {"epoch": 9, "set_hash": "persisted-set-hash"}},
    }
    assert _current_validator_set_hash_from_state(state) == "persisted-set-hash"
