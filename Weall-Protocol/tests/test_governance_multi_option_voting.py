from __future__ import annotations

import copy
import json

import pytest

from weall.runtime.apply.governance import apply_governance
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _state(validators: list[str] | None = None) -> dict:
    vals = validators or ["@alice", "@bob", "@carol"]
    return {
        "height": 10,
        "accounts": {acct: {"poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 6000} for acct in vals},
        "roles": {"validators": {"active_set": list(vals), "by_id": {acct: {"active": True} for acct in vals}}},
        "gov_proposals_by_id": {},
        "system_queue": [],
    }


def _hash(state: dict) -> str:
    return json.dumps(state, sort_keys=True, separators=(",", ":"))


def test_multi_option_proposal_canonicalizes_option_ids_and_order() -> None:
    st = _state()

    apply_governance(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-options",
                "title": "Choose a launch prep route",
                "rules": {"start_stage": "voting"},
                "options": [
                    {"option_id": "z-route", "label": "Route Z"},
                    {"option_id": "a-route", "label": "Route A"},
                    "Text fallback option",
                ],
            },
        ),
    )

    proposal = st["gov_proposals_by_id"]["p-options"]
    option_ids = [opt["option_id"] for opt in proposal["options"]]
    assert option_ids == sorted(option_ids)
    assert "a-route" in option_ids
    assert "z-route" in option_ids
    assert proposal["vote_model"] == "multi_option_plurality"
    assert proposal["created_at_height"] == 11
    assert proposal["voting_opened_at_height"] == 11


def test_invalid_and_duplicate_options_are_rejected_deterministically() -> None:
    st = _state()

    with pytest.raises(ApplyError) as one_option:
        apply_governance(
            st,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@alice",
                1,
                {"proposal_id": "p-one", "rules": {"start_stage": "voting"}, "options": [{"option_id": "only", "label": "Only"}]},
            ),
        )
    assert one_option.value.reason == "proposal_options_require_at_least_two"

    with pytest.raises(ApplyError) as duplicate:
        apply_governance(
            st,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@alice",
                2,
                {
                    "proposal_id": "p-dup",
                    "rules": {"start_stage": "voting"},
                    "options": [
                        {"option_id": "same", "label": "First"},
                        {"option_id": "same", "label": "Second"},
                        {"option_id": "other", "label": "Other"},
                    ],
                },
            ),
        )
    assert duplicate.value.reason == "proposal_option_duplicate_id"


def test_multi_option_votes_reference_option_ids_and_reject_unknown_options() -> None:
    st = _state()
    apply_governance(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-vote",
                "title": "Vote by canonical option id",
                "rules": {"start_stage": "voting"},
                "options": [{"option_id": "north", "label": "North"}, {"option_id": "south", "label": "South"}],
            },
        ),
    )

    with pytest.raises(ApplyError) as invalid:
        apply_governance(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-vote", "option_id": "east"}))
    assert invalid.value.reason == "invalid_option_vote"
    assert invalid.value.details["allowed_option_ids"] == ["north", "south", "abstain"]

    apply_governance(st, _env("GOV_VOTE_CAST", "@alice", 3, {"proposal_id": "p-vote", "option_id": "north"}))
    vote = st["gov_proposals_by_id"]["p-vote"]["votes"]["@alice"]
    assert vote == {"vote": "north", "height": 11, "option_id": "north"}


def test_duplicate_multi_option_vote_replaces_prior_choice_before_quorum() -> None:
    st = _state()
    apply_governance(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-replace",
                "title": "Replacement semantics",
                "rules": {"start_stage": "voting"},
                "options": [{"option_id": "alpha", "label": "Alpha"}, {"option_id": "beta", "label": "Beta"}],
            },
        ),
    )

    apply_governance(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-replace", "option_id": "alpha"}))
    apply_governance(st, _env("GOV_VOTE_CAST", "@alice", 3, {"proposal_id": "p-replace", "option_id": "beta"}))
    proposal = st["gov_proposals_by_id"]["p-replace"]
    assert proposal["votes"]["@alice"]["option_id"] == "beta"
    assert proposal["stage"] == "voting"

    apply_governance(st, _env("GOV_VOTE_CAST", "@bob", 4, {"proposal_id": "p-replace", "option_id": "beta"}))
    latest = proposal["tallies"][-1]["payload"]
    assert proposal["stage"] == "finalized"
    assert latest["selected_option_id"] == "beta"
    assert latest["option_tallies"] == {"alpha": 0, "beta": 2}
    assert latest["passed"] is True


def test_multi_option_abstain_quorum_and_tie_have_no_automatic_winner() -> None:
    st = _state(["@alice", "@bob", "@carol", "@dina"])
    apply_governance(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-tie",
                "title": "Tie handling",
                "rules": {"start_stage": "voting"},
                "options": [{"option_id": "alpha", "label": "Alpha"}, {"option_id": "beta", "label": "Beta"}],
            },
        ),
    )

    apply_governance(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-tie", "option_id": "alpha"}))
    apply_governance(st, _env("GOV_VOTE_CAST", "@bob", 3, {"proposal_id": "p-tie", "option_id": "beta"}))
    apply_governance(st, _env("GOV_VOTE_CAST", "@carol", 4, {"proposal_id": "p-tie", "vote": "abstain"}))

    proposal = st["gov_proposals_by_id"]["p-tie"]
    latest = proposal["tallies"][-1]["payload"]
    assert latest["quorum_met"] is True
    assert latest["option_tallies"] == {"alpha": 1, "beta": 1}
    assert latest["abstain"] == 1
    assert latest["tie"] is True
    assert latest["tie_option_ids"] == ["alpha", "beta"]
    assert latest["selected_option_id"] == ""
    assert latest["passed"] is False
    assert latest["deterministic_tie_break"] == "no automatic winner; tied option_ids are published in lexicographic order"
    assert proposal["stage"] == "finalized"


def test_multi_option_proposals_cannot_carry_executable_actions_in_testnet_slice() -> None:
    st = _state()
    st["params"] = {"gov_action_allowlist": ["GOV_QUORUM_SET"]}

    with pytest.raises(ApplyError) as exc:
        apply_governance(
            st,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@alice",
                1,
                {
                    "proposal_id": "p-action",
                    "rules": {"start_stage": "voting"},
                    "options": [{"option_id": "alpha", "label": "Alpha"}, {"option_id": "beta", "label": "Beta"}],
                    "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 6000}}],
                },
            ),
        )
    assert exc.value.reason == "multi_option_executable_actions_not_supported"


def test_multi_option_vote_replay_equivalence_for_observer_and_follower() -> None:
    initial = _state(["@alice", "@bob", "@carol", "@dina"])
    txs = [
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-replay",
                "title": "Replay deterministic choice",
                "rules": {"start_stage": "voting"},
                "options": [{"option_id": "alpha", "label": "Alpha"}, {"option_id": "beta", "label": "Beta"}],
            },
        ),
        _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-replay", "option_id": "alpha"}),
        _env("GOV_VOTE_CAST", "@bob", 3, {"proposal_id": "p-replay", "option_id": "alpha"}),
        _env("GOV_VOTE_CAST", "@carol", 4, {"proposal_id": "p-replay", "vote": "abstain"}),
    ]

    leader = copy.deepcopy(initial)
    follower = copy.deepcopy(initial)
    observer = copy.deepcopy(initial)
    for st in (leader, follower, observer):
        for tx in txs:
            apply_governance(st, tx)

    assert _hash(leader) == _hash(follower) == _hash(observer)
    latest = leader["gov_proposals_by_id"]["p-replay"]["tallies"][-1]["payload"]
    assert latest["selected_option_id"] == "alpha"
