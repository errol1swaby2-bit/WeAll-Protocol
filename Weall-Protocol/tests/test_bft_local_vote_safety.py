from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def test_local_vote_is_monotonic_and_non_equivocating() -> None:
    bft = HotStuffBFT(chain_id="weall:test")

    assert bft.record_local_vote(view=1, block_id="B1") is True

    # Same view, same block is idempotent.
    assert bft.record_local_vote(view=1, block_id="B1") is True

    # Same view, different block => equivocation => refused.
    assert bft.record_local_vote(view=1, block_id="B2") is False

    # Lower view => refused.
    assert bft.record_local_vote(view=0, block_id="B0") is False

    # Higher view => allowed.
    assert bft.record_local_vote(view=2, block_id="B2") is True


def test_locked_qc_does_not_move_to_conflicting_branch() -> None:
    bft = HotStuffBFT(chain_id="weall:test")

    # Build two branches from A: A<-B<-C and A<-X
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
    }

    # Start locked on B.
    bft.locked_qc = QuorumCert(chain_id="weall:test", view=1, block_id="B", parent_id="A", votes=tuple())

    # Observe a QC on the conflicting branch X at a higher view.
    qc_x = QuorumCert(chain_id="weall:test", view=9, block_id="X", parent_id="A", votes=tuple())
    bft.observe_qc(blocks=blocks, qc=qc_x)

    # Lock must not move to X because it doesn't extend B.
    assert bft.locked_qc is not None
    assert bft.locked_qc.block_id == "B"

    # Observe a QC on C which extends B.
    qc_c = QuorumCert(chain_id="weall:test", view=10, block_id="C", parent_id="B", votes=tuple())
    bft.observe_qc(blocks=blocks, qc=qc_c)
    assert bft.locked_qc is not None
    assert bft.locked_qc.block_id == "C"
