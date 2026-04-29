from __future__ import annotations

import pytest

from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="")


def test_group_emissary_election_window_enforced() -> None:
    state = {"height": 100}

    # Create group at height 101.
    apply_groups(state, _env("GROUP_CREATE", "@alice", 1, {"group_id": "gwin", "charter": "x"}))

    # Inject members directly.
    g = state["roles"]["groups_by_id"]["gwin"]
    g["members"] = {
        "@alice": {"joined_at_nonce": 1},
        "@bob": {"joined_at_nonce": 1},
        "@carl": {"joined_at_nonce": 1},
        "@dana": {"joined_at_nonce": 1},
        "@erin": {"joined_at_nonce": 1},
    }

    # Create bounded election: start at 105, end at 110.
    apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@alice",
            2,
            {
                "group_id": "gwin",
                "election_id": "e-win",
                "seats": 5,
                "candidates": ["@alice", "@bob", "@carl", "@dana", "@erin"],
                "start_height": 105,
                "end_height": 110,
            },
        ),
    )

    # Too early: applying at height 104 (< 105)
    state["height"] = 103
    with pytest.raises(GroupsApplyError) as e1:
        apply_groups(
            state,
            _env(
                "GROUP_EMISSARY_BALLOT_CAST",
                "@bob",
                10,
                {"election_id": "e-win", "ranking": ["@bob", "@alice"]},
            ),
        )
    assert e1.value.reason == "election_not_started"

    # On time: applying at height 105
    state["height"] = 104
    meta = apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_BALLOT_CAST",
            "@bob",
            11,
            {"election_id": "e-win", "ranking": ["@bob", "@alice"]},
        ),
    )
    assert meta and meta["applied"] == "GROUP_EMISSARY_BALLOT_CAST"

    # Finalize too early: applying at height 109 (< 110)
    state["height"] = 108
    with pytest.raises(GroupsApplyError) as e2:
        apply_groups(
            state, _env("GROUP_EMISSARY_ELECTION_FINALIZE", "@alice", 20, {"election_id": "e-win"})
        )
    assert e2.value.reason == "election_still_open"

    # Too late to vote: applying at height 110 (>= 110)
    state["height"] = 109
    with pytest.raises(GroupsApplyError) as e3:
        apply_groups(
            state,
            _env(
                "GROUP_EMISSARY_BALLOT_CAST",
                "@carl",
                30,
                {"election_id": "e-win", "ranking": ["@carl", "@alice"]},
            ),
        )
    assert e3.value.reason == "election_closed"

    # Finalize on/after end: applying at height 110
    state["height"] = 109
    meta2 = apply_groups(
        state, _env("GROUP_EMISSARY_ELECTION_FINALIZE", "@alice", 40, {"election_id": "e-win"})
    )
    assert meta2 and meta2["applied"] == "GROUP_EMISSARY_ELECTION_FINALIZE"
    winners = state["roles"]["groups_by_id"]["gwin"].get("emissaries")
    assert isinstance(winners, list) and len(winners) >= 5
