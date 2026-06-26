from __future__ import annotations

import pytest

from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="")


def _prepare_group_with_open_election() -> dict:
    state = {"height": 100}
    apply_groups(state, _env("GROUP_CREATE", "@alice", 1, {"group_id": "g-open", "charter": "x"}))
    g = state["roles"]["groups_by_id"]["g-open"]
    g["members"] = {
        "@alice": {"joined_at_nonce": 1},
        "@bob": {"joined_at_nonce": 1},
        "@carl": {"joined_at_nonce": 1},
        "@dana": {"joined_at_nonce": 1},
        "@erin": {"joined_at_nonce": 1},
    }
    apply_groups(
        state,
        _env(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@alice",
            2,
            {
                "group_id": "g-open",
                "election_id": "e-open",
                "seats": 5,
                "candidates": ["@alice", "@bob", "@carl", "@dana", "@erin"],
                "start_height": 101,
                "end_height": 110,
            },
        ),
    )
    return state


def test_group_signers_set_rejects_while_emissary_election_open_batch109() -> None:
    state = _prepare_group_with_open_election()
    with pytest.raises(GroupsApplyError) as exc:
        apply_groups(
            state,
            _env(
                "GROUP_SIGNERS_SET",
                "@alice",
                3,
                {"group_id": "g-open", "signers": ["@alice", "@bob"], "threshold": 2},
            ),
        )
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "group_emissary_election_open"


def test_group_moderators_set_rejects_while_emissary_election_open_batch109() -> None:
    state = _prepare_group_with_open_election()
    with pytest.raises(GroupsApplyError) as exc:
        apply_groups(
            state,
            _env(
                "GROUP_MODERATORS_SET",
                "@alice",
                4,
                {"group_id": "g-open", "moderators": ["@alice", "@bob"]},
            ),
        )
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "group_emissary_election_open"


def test_group_signers_set_allowed_after_election_finalize_batch109() -> None:
    state = _prepare_group_with_open_election()
    state["height"] = 109
    meta = apply_groups(state, _env("GROUP_EMISSARY_ELECTION_FINALIZE", "@alice", 10, {"election_id": "e-open"}))
    assert meta and meta["applied"] == "GROUP_EMISSARY_ELECTION_FINALIZE"

    meta2 = apply_groups(
        state,
        _env(
            "GROUP_SIGNERS_SET",
            "@alice",
            11,
            {"group_id": "g-open", "signers": ["@alice", "@bob", "@carl"], "threshold": 2},
        ),
    )
    assert meta2 and meta2["applied"] == "GROUP_SIGNERS_SET"
