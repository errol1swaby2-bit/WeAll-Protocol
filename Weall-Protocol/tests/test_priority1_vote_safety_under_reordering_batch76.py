from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT


def test_vote_once_per_view_enforced_under_reordering_batch76() -> None:
    hs = HotStuffBFT(chain_id="batch76")

    assert hs.record_local_vote(view=10, block_id="A") is True
    assert hs.record_local_vote(view=10, block_id="B") is False


def test_vote_progression_allows_new_view_after_roundtrip_batch76() -> None:
    hs = HotStuffBFT(chain_id="batch76")

    assert hs.record_local_vote(view=10, block_id="A") is True

    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch76")
    hs2.load_from_state({"bft": state})

    assert hs2.record_local_vote(view=11, block_id="B") is True


def test_stale_view_vote_rejected_after_higher_vote_batch76() -> None:
    hs = HotStuffBFT(chain_id="batch76")

    assert hs.record_local_vote(view=11, block_id="B") is True
    assert hs.record_local_vote(view=10, block_id="A") is False


def test_vote_state_roundtrip_consistency_batch76() -> None:
    hs = HotStuffBFT(chain_id="batch76")

    hs.record_local_vote(view=9, block_id="Z")
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch76")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert int(state2.get("last_voted_view") or 0) == 9
    assert str(state2.get("last_voted_block_id") or "") == "Z"
