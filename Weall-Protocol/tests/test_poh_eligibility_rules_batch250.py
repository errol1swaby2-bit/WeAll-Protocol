from __future__ import annotations

import pytest

from weall.runtime.errors import ApplyError
from weall.runtime.poh.eligibility import get_required_poh_tier, require_poh_tier
from weall.runtime.poh.state import set_account_poh_status


def _state(tier: int) -> dict:
    state = {"height": 5, "accounts": {"@alice": {"account_id": "@alice", "poh_tier": tier}}, "poh": {}}
    if tier:
        set_account_poh_status(state, account_id="@alice", poh_tier=tier, verified_at_height=5, last_updated_height=5)
    return state


def test_required_tiers_for_v2_two_tier_migration_gates() -> None:
    assert get_required_poh_tier("GROUP_MEMBERSHIP_REQUEST") == 1
    assert get_required_poh_tier("GROUP_CREATE") == 2
    assert get_required_poh_tier("GOV_VOTE_CAST") == 2


def test_tier1_cannot_vote_governance() -> None:
    with pytest.raises(ApplyError) as exc:
        require_poh_tier(_state(1), "@alice", "GOV_VOTE_CAST")
    assert exc.value.reason == "poh_tier_required"
    assert exc.value.details["required_tier"] == 2


def test_tier2_can_create_group_and_register_oracle_after_v2_remap() -> None:
    state = _state(2)
    require_poh_tier(state, "@alice", "GROUP_CREATE")
