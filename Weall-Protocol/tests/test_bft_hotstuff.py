from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert, quorum_threshold


def test_quorum_thresholds() -> None:
    # n=4 => f=1 => 2f+1=3
    assert quorum_threshold(4) == 3
    # n=7 => f=2 => 2f+1=5
    assert quorum_threshold(7) == 5
    # n<1 => 0
    assert quorum_threshold(0) == 0


def test_locked_rule_descendant_enforced() -> None:
    bft = HotStuffBFT(chain_id="weall:test")

    # Build a toy chain A <- B <- C
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": ""},  # unrelated branch
    }

    bft.locked_qc = QuorumCert(chain_id="weall:test", view=1, block_id="B", parent_id="A", votes=tuple())

    assert bft.can_vote_for(blocks=blocks, block_id="C") is True
    assert bft.can_vote_for(blocks=blocks, block_id="B") is True
    assert bft.can_vote_for(blocks=blocks, block_id="A") is False
    assert bft.can_vote_for(blocks=blocks, block_id="X") is False


def test_hotstuff_3chain_commit_advances_finality() -> None:
    bft = HotStuffBFT(chain_id="weall:test")

    # Chain: A <- B1 <- B2 <- B3
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "B2": {"prev_block_id": "B1"},
        "B3": {"prev_block_id": "B2"},
    }

    qc = QuorumCert(chain_id="weall:test", view=10, block_id="B3", parent_id="B2", votes=tuple())

    finalized = bft.observe_qc(blocks=blocks, qc=qc)
    assert finalized == "B1"
    assert bft.finalized_block_id == "B1"
    assert bft.finalized_view == 10
