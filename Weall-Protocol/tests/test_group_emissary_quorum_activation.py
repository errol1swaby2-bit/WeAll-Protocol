"""Versioned group emissary quorum: identical default participation threshold to governance.

No activation is set in production. Synthetic canonical apply tests cover a
governance-controlled activation parameter, historical non-retroactivity,
frozen electorate size, strict ballot counting and treasury non-mutation.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.apply.governance import _electorate_required_votes
from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.param_policy import validate_param
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="")


def _setup(
    *, eligible: int = 5, activation: int | None = 101, strict: bool = False
) -> tuple[dict, dict, list[str]]:
    voters = [f"@v{index:02d}" for index in range(eligible)]
    params: dict = {}
    if activation is not None:
        params["group_emissary_quorum_activation_height"] = activation
    state: dict = {"height": 100, "params": params}
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


def test_zero_ballots_after_activation_preserve_existing_treasury_authority() -> None:
    state, group, _ = _setup()
    before = deepcopy(state["roles"]["treasuries_by_id"][group["treasury_id"]])
    result = _finish(state)
    assert result["status"] == "no_decision"
    assert result["reason"] == "no_valid_ballots"
    assert result["required_votes"] == 4
    assert result["n_ballots"] == 0
    assert state["roles"]["treasuries_by_id"][group["treasury_id"]] == before
