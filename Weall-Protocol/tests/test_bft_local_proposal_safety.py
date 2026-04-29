from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT


def test_record_local_proposal_prevents_same_view_equivocation() -> None:
    bft = HotStuffBFT(chain_id="weall-test")

    assert bft.record_local_proposal(view=5, block_id="b5") is True
    assert bft.record_local_proposal(view=5, block_id="b5") is True
    assert bft.record_local_proposal(view=5, block_id="b5-conflict") is False
    assert bft.record_local_proposal(view=4, block_id="b4") is False
    assert bft.record_local_proposal(view=6, block_id="b6") is True


def test_record_local_proposal_persists_across_restart() -> None:
    a = HotStuffBFT(chain_id="weall-test")
    assert a.record_local_proposal(view=9, block_id="b9") is True

    snap = {"bft": a.export_state()}

    b = HotStuffBFT(chain_id="weall-test")
    b.load_from_state(snap)

    assert b.record_local_proposal(view=9, block_id="b9") is True
    assert b.record_local_proposal(view=9, block_id="b9-alt") is False
