"""Versioned group emissary quorum: identical default participation threshold to governance.

No activation is set in production. Synthetic canonical apply tests cover a
governance-controlled activation parameter, historical non-retroactivity,
frozen electorate size, strict ballot counting and treasury non-mutation.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.apply.governance import _active_group_member_ids, _electorate_required_votes
from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.param_policy import validate_param
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="")


def _setup(
    *,
    eligible: int = 5,
    activation: int | None = 101,
    strict: bool = False,
    account_overrides: dict[str, dict | None] | None = None,
    membership_overrides: dict[str, dict] | None = None,
) -> tuple[dict, dict, list[str]]:
    voters = [f"@v{index:02d}" for index in range(eligible)]
    params: dict = {}
    if activation is not None:
        params["group_emissary_quorum_activation_height"] = activation
    state: dict = {
        "height": 100,
        "params": params,
        "accounts": {voter: {"poh_tier": 2} for voter in voters},
    }
    if account_overrides:
        for account, record in account_overrides.items():
            if record is None:
                state["accounts"].pop(account, None)
            else:
                state["accounts"][account] = record
    if strict:
        state["chain_id"] = "weall-controlled-testnet"
        params["mode"] = "controlled-testnet"
        state["ballot_profile"] = {
            "profile_id": "controlled-testnet-aggregate-v1",
            "active": True,
        }
    apply_groups(
        state,
        _env("GROUP_CREATE", "@creator", 1, {"group_id": "g:quorum", "charter": "test"}),
    )
    group = state["roles"]["groups_by_id"]["g:quorum"]
    group["members"] = {voter: {"joined_at_nonce": 1} for voter in voters}
    if membership_overrides:
        group["members"].update(membership_overrides)
    apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@creator",
            2,
            {
                "group_id": "g:quorum",
                "election_id": "e:quorum",
                "seats": 5,
                "candidates": voters[:5],
                "start_height": 101,
                "end_height": 103,
            },
        ),
    )
    return state, group, voters


def _cast(state: dict, voter: str, nonce: int) -> None:
    result = apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_BALLOT_CAST",
            voter,
            nonce,
            {"election_id": "e:quorum", "ranking": ["@v00"]},
        ),
    )
    assert result["applied"] == "GROUP_EMISSARY_BALLOT_CAST"


def _finish(state: dict) -> dict:
    state["height"] = 102
    return apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_ELECTION_FINALIZE",
            "@creator",
            90,
            {"group_id": "g:quorum", "election_id": "e:quorum"},
        ),
    )


@pytest.mark.parametrize("eligible,required", [(1, 1), (2, 2), (3, 2), (5, 4), (20, 14)])
def test_default_election_quorum_matches_regular_governance(eligible: int, required: int) -> None:
    assert quorum_threshold(eligible) == required
    assert _electorate_required_votes({}, eligible) == required


@pytest.mark.parametrize("strict", [False, True], ids=["legacy_ballots", "strict_aggregate"])
def test_unmet_quorum_records_no_decision_and_preserves_authority(strict: bool) -> None:
    state, group, voters = _setup(eligible=20, strict=strict)
    election = state["group_emissary_elections"]["e:quorum"]
    assert election["required_votes"] == 14
    assert election["eligible_voter_count"] == 20
    before_group = deepcopy(group)
    before_treasury = deepcopy(state["roles"]["treasuries_by_id"][group["treasury_id"]])
    for index, voter in enumerate(voters[:13], 10):
        _cast(state, voter, index)
    result = _finish(state)
    assert result["status"] == "no_decision"
    assert result["reason"] == "quorum_unmet"
    assert result["n_ballots"] == 13
    assert result["required_votes"] == 14
    assert result["quorum_met"] is False
    assert group == before_group
    assert state["roles"]["treasuries_by_id"][group["treasury_id"]] == before_treasury
    repeated = _finish(state)
    assert repeated["deduped"] is True
    assert repeated["reason"] == "quorum_unmet"
    assert group == before_group


@pytest.mark.parametrize("strict", [False, True], ids=["legacy_ballots", "strict_aggregate"])
def test_quorum_met_allows_existing_intended_redistribution(strict: bool) -> None:
    state, group, voters = _setup(eligible=20, strict=strict)
    for index, voter in enumerate(voters[:14], 10):
        _cast(state, voter, index)
    outcome = _finish(state)
    election = state["group_emissary_elections"]["e:quorum"]
    assert election["quorum_met"] is True
    assert election["n_ballots"] == 14
    assert election["status"] == "finalized"
    assert len(outcome["winners"]) == 5
    assert group["signers"] == outcome["winners"]
    assert state["roles"]["treasuries_by_id"][group["treasury_id"]]["signers"] == outcome["winners"]


def test_pre_activation_election_retains_historical_rule_after_activation_height() -> None:
    state, group, voters = _setup(eligible=20, activation=102)
    election = state["group_emissary_elections"]["e:quorum"]
    assert "quorum_policy_version" not in election
    assert "required_votes" not in election
    _cast(state, voters[0], 10)
    result = _finish(state)
    assert result["n_ballots"] == 1
    assert election["status"] == "finalized"
    assert len(group["signers"]) == 5


def test_no_activation_parameter_preserves_legacy_election_semantics() -> None:
    state, _, voters = _setup(eligible=20, activation=None)
    assert "quorum_policy_version" not in state["group_emissary_elections"]["e:quorum"]
    _cast(state, voters[0], 10)
    assert _finish(state)["n_ballots"] == 1


def test_activation_parameter_is_explicitly_governance_whitelisted() -> None:
    path = ("params", "group_emissary_quorum_activation_height")
    validate_param(path, 101)
    with pytest.raises(ValueError):
        validate_param(path, 0)
    with pytest.raises(ValueError):
        validate_param(path, 2_147_483_648)


def test_invalid_quorum_snapshot_fails_closed_before_signer_transfer() -> None:
    state, group, voters = _setup()
    for index, voter in enumerate(voters[:4], 10):
        _cast(state, voter, index)
    election = state["group_emissary_elections"]["e:quorum"]
    election["required_votes"] = 1
    with pytest.raises(GroupsApplyError) as exc:
        _finish(state)
    assert exc.value.reason == "emissary_quorum_snapshot_mismatch"
    assert group["signers"] == ["@creator"]


def test_activated_electorate_matches_regular_group_governance_exactly() -> None:
    overrides = {
        "@v01": {"poh_tier": 1},
        "@v02": {"poh_tier": 2, "banned": True},
        "@v03": {"poh_tier": 2, "locked": True},
        "@v04": {"poh_tier": 2, "suspended": True},
        "@v05": None,
        "@v06": {"poh_tier": 3},
    }
    memberships = {
        "@v07": {"status": "removed"},
        "@v08": {"active": False},
        "@v09": {"status": "rejected"},
    }
    state, group, voters = _setup(
        eligible=10,
        account_overrides=overrides,
        membership_overrides=memberships,
    )
    governed = _active_group_member_ids(state, {"group_id": "g:quorum"})
    assert governed == ["@v00", "@v06"]
    election = state["group_emissary_elections"]["e:quorum"]
    assert election["voter_snapshot"] == governed
    assert election["eligible_voter_count"] == len(governed)
    assert election["required_votes"] == 2
    assert election["electorate_source"] == "group_governance_active_group_members_tier2"
    with pytest.raises(GroupsApplyError) as exc:
        _cast(state, voters[1], 41)
    assert exc.value.reason == "voter_not_in_snapshot"
    before_group = deepcopy(group)
    before_treasury = deepcopy(state["roles"]["treasuries_by_id"][group["treasury_id"]])
    _cast(state, voters[0], 42)
    insufficient = _finish(state)
    assert insufficient["status"] == "no_decision"
    assert insufficient["required_votes"] == 2
    assert group == before_group
    assert state["roles"]["treasuries_by_id"][group["treasury_id"]] == before_treasury


def test_activated_snapshot_freezes_eligibility_across_account_and_membership_changes() -> None:
    state, group, voters = _setup(eligible=5)
    election = state["group_emissary_elections"]["e:quorum"]
    frozen = list(election["voter_snapshot"])
    group["members"]["@late"] = {"joined_at_nonce": 2}
    state["accounts"]["@late"] = {"poh_tier": 3}
    group["members"][voters[0]]["status"] = "removed"
    state["accounts"][voters[0]]["banned"] = True
    assert election["voter_snapshot"] == frozen
    with pytest.raises(GroupsApplyError) as exc:
        _cast(state, "@late", 55)
    assert exc.value.reason == "voter_not_in_snapshot"
    # Consistent with governance's frozen electorate: later account changes do
    # not mutate a snapshot. Upstream signed admission may add further gates.
    _cast(state, voters[0], 56)


def test_activated_election_with_no_governance_eligible_voters_fails_closed() -> None:
    low_tier = {f"@v{i:02d}": {"poh_tier": 1} for i in range(5)}
    with pytest.raises(GroupsApplyError) as exc:
        _setup(eligible=5, account_overrides=low_tier)
    assert exc.value.reason == "no_eligible_group_electorate"


def test_legacy_electorate_remains_unfiltered_without_activation() -> None:
    low_tier = {f"@v{i:02d}": {"poh_tier": 1} for i in range(5)}
    state, _, voters = _setup(eligible=5, activation=None, account_overrides=low_tier)
    election = state["group_emissary_elections"]["e:quorum"]
    assert election["voter_snapshot"] == voters
    assert "electorate_source" not in election
    assert "required_votes" not in election
    assert _active_group_member_ids(state, {"group_id": "g:quorum"}) == []


def test_corrupt_activated_electorate_source_fails_closed_before_authority_change() -> None:
    state, group, voters = _setup(eligible=5)
    for index, voter in enumerate(voters[:4], 10):
        _cast(state, voter, index)
    election = state["group_emissary_elections"]["e:quorum"]
    election["electorate_source"] = "untrusted_raw_member_snapshot"
    with pytest.raises(GroupsApplyError) as exc:
        _finish(state)
    assert exc.value.reason == "emissary_electorate_snapshot_mismatch"
    assert group["signers"] == ["@creator"]


def test_zero_ballots_after_activation_preserve_existing_treasury_authority() -> None:
    state, group, _ = _setup()
    before = deepcopy(state["roles"]["treasuries_by_id"][group["treasury_id"]])
    result = _finish(state)
    assert result["status"] == "no_decision"
    assert result["reason"] == "no_valid_ballots"
    assert result["required_votes"] == 4
    assert result["n_ballots"] == 0
    assert state["roles"]["treasuries_by_id"][group["treasury_id"]] == before
