from __future__ import annotations

from weall.ledger.state import LedgerView
from weall.runtime.apply.groups import apply_groups
from weall.runtime.gates import resolve_signer_authz
from weall.runtime.tx_admission_types import TxEnvelope


def _mk_env(tx_type: str, signer: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="")


def test_group_emissary_election_stv_min_five_and_sets_treasury_signers() -> None:
    # Explicit height so election windows are meaningful.
    state = {"height": 100}

    # Create a group (auto-creates group treasury and signer set in state.roles)
    env_create = _mk_env("GROUP_CREATE", "@alice", 1, {"group_id": "g1", "charter": "x"})
    meta = apply_groups(state, env_create)
    assert meta and meta["applied"] == "GROUP_CREATE"

    # Inject members directly (membership flow is orthogonal to STV correctness)
    g = state["roles"]["groups_by_id"]["g1"]
    g["members"] = {
        "@alice": {"joined_at_nonce": 1},
        "@bob": {"joined_at_nonce": 1},
        "@carl": {"joined_at_nonce": 1},
        "@dana": {"joined_at_nonce": 1},
        "@erin": {"joined_at_nonce": 1},
        "@faye": {"joined_at_nonce": 1},
        "@gary": {"joined_at_nonce": 1},
    }

    # Election: 5 seats, 6 candidates
    candidates = ["@alice", "@bob", "@carl", "@dana", "@erin", "@faye"]
    env_elect = _mk_env(
        "GROUP_EMISSARY_ELECTION_CREATE",
        "@alice",
        2,
        {
            "group_id": "g1",
            "election_id": "e1",
            "seats": 5,
            "candidates": candidates,
            # Short bounded window so the test can finalize immediately.
            "start_height": 101,
            "end_height": 103,
        },
    )
    meta = apply_groups(state, env_elect)
    assert meta and meta["applied"] == "GROUP_EMISSARY_ELECTION_CREATE"

    # Ballots (simple rankings)
    ballots = {
        "@alice": ["@alice", "@bob", "@carl", "@dana", "@erin", "@faye"],
        "@bob": ["@bob", "@carl", "@dana", "@erin", "@faye", "@alice"],
        "@carl": ["@carl", "@dana", "@erin", "@faye", "@bob", "@alice"],
        "@dana": ["@dana", "@erin", "@faye", "@carl", "@bob", "@alice"],
        "@erin": ["@erin", "@faye", "@dana", "@carl", "@bob", "@alice"],
        "@faye": ["@faye", "@erin", "@dana", "@carl", "@bob", "@alice"],
        "@gary": ["@bob", "@carl", "@dana", "@erin", "@faye", "@alice"],
    }

    n = 10
    for voter, ranking in ballots.items():
        meta = apply_groups(
            state,
            _mk_env(
                "GROUP_EMISSARY_BALLOT_CAST", voter, n, {"election_id": "e1", "ranking": ranking}
            ),
        )
        assert meta and meta["applied"] == "GROUP_EMISSARY_BALLOT_CAST"
        n += 1

    # Advance chain height so finalize occurs at now_h >= end_height.
    # now_h = state.height + 1
    state["height"] = 102

    # Finalize
    meta = apply_groups(
        state, _mk_env("GROUP_EMISSARY_ELECTION_FINALIZE", "@alice", 99, {"election_id": "e1"})
    )
    assert meta and meta["applied"] == "GROUP_EMISSARY_ELECTION_FINALIZE"

    winners = state["roles"]["groups_by_id"]["g1"].get("emissaries")
    assert isinstance(winners, list)
    assert len(winners) >= 5

    # Group treasury signers should now be the emissaries
    treasury_id = state["roles"]["groups_by_id"]["g1"].get("treasury_id")
    assert isinstance(treasury_id, str) and treasury_id
    treas = state["roles"]["treasuries_by_id"][treasury_id]
    assert treas.get("require_emissary_signers") is True
    assert sorted(treas.get("signers", [])) == sorted(winners)
    assert int(treas.get("threshold", 0)) >= 2


def test_gate_emissary_accepts_group_emissary_after_election() -> None:
    state = {"height": 200}

    apply_groups(state, _mk_env("GROUP_CREATE", "@alice", 1, {"group_id": "g2", "charter": "x"}))
    g = state["roles"]["groups_by_id"]["g2"]
    g["members"] = {
        "@alice": {"joined_at_nonce": 1},
        "@bob": {"joined_at_nonce": 1},
        "@carl": {"joined_at_nonce": 1},
        "@dana": {"joined_at_nonce": 1},
        "@erin": {"joined_at_nonce": 1},
    }

    apply_groups(
        state,
        _mk_env(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@alice",
            2,
            {
                "group_id": "g2",
                "election_id": "e2",
                "seats": 5,
                "candidates": ["@alice", "@bob", "@carl", "@dana", "@erin"],
                "start_height": 201,
                "end_height": 203,
            },
        ),
    )

    for i, voter in enumerate(["@alice", "@bob", "@carl", "@dana", "@erin"], start=10):
        apply_groups(
            state,
            _mk_env(
                "GROUP_EMISSARY_BALLOT_CAST",
                voter,
                i,
                {"election_id": "e2", "ranking": ["@alice", "@bob", "@carl", "@dana", "@erin"]},
            ),
        )

    # Advance to end_height (now_h = state.height + 1)
    state["height"] = 202

    apply_groups(
        state, _mk_env("GROUP_EMISSARY_ELECTION_FINALIZE", "@alice", 99, {"election_id": "e2"})
    )

    winners = state["roles"]["groups_by_id"]["g2"]["emissaries"]
    assert winners
    signer = winners[0]

    lv = LedgerView.from_ledger(state)
    ok, meta = resolve_signer_authz(
        ledger=lv, signer=signer, gate_expr="Emissary", payload={"group_id": "g2"}
    )
    assert ok is True
    assert meta == {}

    ok2, meta2 = resolve_signer_authz(
        ledger=lv, signer="@notemissary", gate_expr="Emissary", payload={"group_id": "g2"}
    )
    assert ok2 is False
    assert isinstance(meta2, dict)
