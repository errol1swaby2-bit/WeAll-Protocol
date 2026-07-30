from __future__ import annotations

from weall.runtime.apply.governance import apply_governance
from weall.runtime.gov_engine import tick_governance_lifecycle
from weall.runtime.tx_admission_types import TxEnvelope


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
        sig="",
        system=system,
        parent=parent,
    )


def _state() -> dict:
    return {
        "height": 100,
        "accounts": {
            "@alice": {"poh_tier": 2, "banned": False, "locked": False},
            "@bob": {"poh_tier": 2, "banned": False, "locked": False},
            "@carol": {"poh_tier": 2, "banned": False, "locked": False},
            "@validator-only": {"poh_tier": 1, "banned": False, "locked": False},
        },
        "roles": {
            "validators": {
                "active_set": ["@validator-only"],
                "by_id": {"@validator-only": {"active": True}},
            }
        },
        "gov_proposals_by_id": {},
        "system_queue": [],
    }


def _create_protocol_vote(state: dict, proposal_id: str = "m3-rounds") -> dict:
    result = apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": proposal_id,
                "title": "Versioned electorate round",
                "rules": {
                    "start_stage": "voting",
                    "electorate_scope": "protocol_tier2",
                    "voting_period_blocks": 10,
                    "max_voting_rounds": 3,
                    "quorum_bps": 6700,
                },
            },
        ),
    )
    assert result and result["applied"] is True
    return state["gov_proposals_by_id"][proposal_id]


def test_protocol_vote_uses_tier2_humans_not_validator_set() -> None:
    state = _state()
    proposal = _create_protocol_vote(state)

    assert proposal["electorate_scope"] == "protocol_tier2"
    assert proposal["electorate_round"] == 1
    assert proposal["eligible_voter_ids"] == ["@alice", "@bob", "@carol"]
    assert proposal["eligible_voter_count"] == 3
    assert "@validator-only" not in proposal["eligible_voter_ids"]

    rounds = proposal["electorate_rounds"]
    assert len(rounds) == 1
    assert rounds[0]["round"] == 1
    assert rounds[0]["opened_at_height"] == 101
    assert rounds[0]["eligible_voter_ids"] == ["@alice", "@bob", "@carol"]
    assert rounds[0]["denominator"] == 3


def test_quorum_unmet_refresh_opens_new_round_without_mutating_prior_round() -> None:
    state = _state()
    proposal = _create_protocol_vote(state)

    apply_governance(
        state,
        _env(
            "GOV_VOTE_CAST",
            "@alice",
            2,
            {"proposal_id": proposal["proposal_id"], "vote": "yes"},
        ),
    )

    state["accounts"]["@bob"]["poh_tier"] = 1
    state["accounts"]["@dave"] = {
        "poh_tier": 2,
        "banned": False,
        "locked": False,
    }
    prior_round = dict(proposal["electorate_rounds"][0])
    prior_snapshot = {
        "round": prior_round["round"],
        "opened_at_height": prior_round["opened_at_height"],
        "eligible_voter_ids": list(prior_round["eligible_voter_ids"]),
        "denominator": prior_round["denominator"],
        "required_votes": prior_round["required_votes"],
    }

    result = apply_governance(
        state,
        _env(
            "GOV_STAGE_SET",
            "SYSTEM",
            102,
            {
                "proposal_id": proposal["proposal_id"],
                "stage": "voting",
                "electorate_refresh": True,
                "refresh_reason": "quorum_unmet",
                "_due_height": 102,
            },
            system=True,
            parent="gov:m3-rounds:102",
        ),
    )

    assert result and result["applied"] is True
    assert proposal["electorate_round"] == 2
    assert proposal["eligible_voter_ids"] == ["@alice", "@carol", "@dave"]
    assert proposal["eligible_voter_count"] == 3
    assert proposal["votes"] == {}

    rounds = proposal["electorate_rounds"]
    assert len(rounds) == 2
    assert {
        "round": rounds[0]["round"],
        "opened_at_height": rounds[0]["opened_at_height"],
        "eligible_voter_ids": rounds[0]["eligible_voter_ids"],
        "denominator": rounds[0]["denominator"],
        "required_votes": rounds[0]["required_votes"],
    } == prior_snapshot
    assert rounds[0]["status"] == "closed_no_decision"
    assert rounds[0]["close_reason"] == "quorum_unmet"
    assert rounds[1]["round"] == 2
    assert rounds[1]["opened_at_height"] == 102
    assert rounds[1]["eligible_voter_ids"] == ["@alice", "@carol", "@dave"]


def test_denominator_refresh_is_system_only_and_never_mutates_active_round_in_place() -> None:
    state = _state()
    proposal = _create_protocol_vote(state)

    original = dict(proposal["electorate_rounds"][0])
    state["accounts"]["@bob"]["poh_tier"] = 1

    # Eligibility churn alone must not silently rewrite the active round.
    apply_governance(
        state,
        _env(
            "GOV_VOTE_CAST",
            "@alice",
            2,
            {"proposal_id": proposal["proposal_id"], "vote": "yes"},
        ),
    )
    assert proposal["electorate_rounds"][0] == original
    assert proposal["eligible_voter_count"] == 3

    from weall.runtime.errors import ApplyError
    import pytest

    with pytest.raises(ApplyError) as exc:
        apply_governance(
            state,
            _env(
                "GOV_STAGE_SET",
                "@alice",
                3,
                {
                    "proposal_id": proposal["proposal_id"],
                    "stage": "voting",
                    "electorate_refresh": True,
                    "refresh_reason": "quorum_unmet",
                },
            ),
        )
    assert exc.value.reason == "electorate_refresh_requires_system"


def test_lifecycle_tick_refreshes_quorum_unmet_round_before_closing() -> None:
    state = _state()
    proposal = _create_protocol_vote(state)
    proposal["voting_opened_at_height"] = 101

    queued = tick_governance_lifecycle(state, next_height=111)

    assert queued == 1
    refreshes = [
        item for item in state["system_queue"]
        if item.get("tx_type") == "GOV_STAGE_SET"
        and item.get("payload", {}).get("electorate_refresh") is True
    ]
    assert len(refreshes) == 1
    assert refreshes[0]["payload"]["refresh_reason"] == "quorum_unmet"
    assert not any(item.get("tx_type") == "GOV_VOTING_CLOSE" for item in state["system_queue"])


def test_max_rounds_expire_with_explicit_no_decision_finality() -> None:
    state = _state()
    proposal = _create_protocol_vote(state)
    proposal["electorate_round"] = 3
    proposal["electorate_rounds"][-1]["round"] = 3
    proposal["voting_opened_at_height"] = 101

    queued = tick_governance_lifecycle(state, next_height=111)
    assert queued == 2

    apply_governance(
        state,
        _env(
            "GOV_VOTING_CLOSE",
            "SYSTEM",
            111,
            {"proposal_id": proposal["proposal_id"]},
            system=True,
            parent="gov:m3-rounds:111",
        ),
    )
    apply_governance(
        state,
        _env(
            "GOV_TALLY_PUBLISH",
            "SYSTEM",
            111,
            {
                "proposal_id": proposal["proposal_id"],
                "tally": {"yes": 0, "no": 0, "abstain": 0},
                "total_votes": 0,
                "quorum_required": proposal["required_votes"],
                "quorum_met": False,
                "passed": False,
                "electorate_round": 3,
                "no_decision_reason": "max_voting_rounds_exhausted",
                "finalize_without_execution": True,
            },
            system=True,
            parent="gov:m3-rounds:111",
        ),
    )

    assert proposal["stage"] == "finalized"
    assert proposal["outcome"] == "expired_no_decision"
    assert proposal["no_decision_reason"] == "max_voting_rounds_exhausted"
    assert proposal["electorate_rounds"][-1]["status"] == "expired_no_decision"


def test_failed_refresh_does_not_close_or_rewrite_active_round() -> None:
    from weall.runtime.errors import ApplyError
    import pytest

    state = _state()
    proposal = _create_protocol_vote(state)
    original_round = dict(proposal["electorate_rounds"][0])
    for record in state["accounts"].values():
        if isinstance(record, dict):
            record["poh_tier"] = 1

    with pytest.raises(ApplyError) as exc:
        apply_governance(
            state,
            _env(
                "GOV_STAGE_SET",
                "SYSTEM",
                102,
                {
                    "proposal_id": proposal["proposal_id"],
                    "stage": "voting",
                    "electorate_refresh": True,
                    "refresh_reason": "quorum_unmet",
                },
                system=True,
                parent="gov:m3-rounds:102",
            ),
        )

    assert exc.value.reason == "electorate_refresh_has_no_eligible_voters"
    assert proposal["electorate_round"] == 1
    assert proposal["electorate_rounds"] == [original_round]
    assert proposal["stage"] == "voting"
