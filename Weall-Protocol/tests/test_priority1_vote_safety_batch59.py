from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT


def test_vote_idempotency_same_block_same_view_batch59() -> None:
    hs = HotStuffBFT(chain_id="batch59")

    ok1 = hs.record_local_vote(view=3, block_id="B")
    ok2 = hs.record_local_vote(view=3, block_id="B")

    assert ok1 is True
    # Repeating the exact same vote is idempotent, not equivocation.
    assert ok2 is True

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 3
    assert str(st.get("last_voted_block_id") or "") == "B"


def test_vote_conflict_same_view_different_block_batch59() -> None:
    hs = HotStuffBFT(chain_id="batch59")

    ok1 = hs.record_local_vote(view=3, block_id="B1")
    ok2 = hs.record_local_vote(view=3, block_id="B2")

    assert ok1 is True
    assert ok2 is False  # conflicting vote must be rejected

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 3
    assert str(st.get("last_voted_block_id") or "") == "B1"


def test_vote_monotonic_view_progression_batch59() -> None:
    hs = HotStuffBFT(chain_id="batch59")

    assert hs.record_local_vote(view=2, block_id="B2") is True
    assert hs.record_local_vote(view=3, block_id="B3") is True

    # cannot go backwards
    assert hs.record_local_vote(view=2, block_id="B2-alt") is False

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 3
    assert str(st.get("last_voted_block_id") or "") == "B3"


def test_vote_persists_across_reload_batch59() -> None:
    hs = HotStuffBFT(chain_id="batch59")

    assert hs.record_local_vote(view=4, block_id="B4") is True

    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch59")
    hs2.load_from_state({"bft": state})

    # Same vote after reload remains idempotent.
    assert hs2.record_local_vote(view=4, block_id="B4") is True
    # Conflicting vote after reload must still be rejected.
    assert hs2.record_local_vote(view=4, block_id="X4") is False

    st2 = hs2.export_state()
    assert int(st2.get("last_voted_view") or 0) == 4
    assert str(st2.get("last_voted_block_id") or "") == "B4"
