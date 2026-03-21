from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT


def test_duplicate_same_vote_is_idempotent_batch87() -> None:
    hs = HotStuffBFT(chain_id="batch87")

    assert hs.record_local_vote(view=12, block_id="B12") is True
    # Exact same vote should remain idempotent.
    assert hs.record_local_vote(view=12, block_id="B12") is True

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 12
    assert str(st.get("last_voted_block_id") or "") == "B12"


def test_conflicting_same_view_vote_is_rejected_batch87() -> None:
    hs = HotStuffBFT(chain_id="batch87")

    assert hs.record_local_vote(view=12, block_id="B12a") is True
    assert hs.record_local_vote(view=12, block_id="B12b") is False

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 12
    assert str(st.get("last_voted_block_id") or "") == "B12a"


def test_vote_replay_after_roundtrip_preserves_first_choice_batch87() -> None:
    hs = HotStuffBFT(chain_id="batch87")

    assert hs.record_local_vote(view=13, block_id="B13") is True
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch87")
    hs2.load_from_state({"bft": state1})

    # Replaying the same vote is still idempotent.
    assert hs2.record_local_vote(view=13, block_id="B13") is True
    # Conflicting vote after reload must still be rejected.
    assert hs2.record_local_vote(view=13, block_id="B13x") is False

    state2 = hs2.export_state()
    assert int(state2.get("last_voted_view") or 0) == 13
    assert str(state2.get("last_voted_block_id") or "") == "B13"


def test_higher_view_vote_advances_but_lower_view_replay_fails_batch87() -> None:
    hs = HotStuffBFT(chain_id="batch87")

    assert hs.record_local_vote(view=14, block_id="B14") is True
    assert hs.record_local_vote(view=15, block_id="B15") is True

    # Lower/stale replay attempt must fail.
    assert hs.record_local_vote(view=14, block_id="B14") is False
    assert hs.record_local_vote(view=14, block_id="B14x") is False

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 15
    assert str(st.get("last_voted_block_id") or "") == "B15"
