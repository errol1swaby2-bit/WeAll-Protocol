from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def test_can_vote_for_allows_higher_justify_qc_across_locked_branch() -> None:
    bft = HotStuffBFT(chain_id="weall:test")
    bft.locked_qc = QuorumCert(
        chain_id="weall:test",
        view=5,
        block_id="B",
        block_hash="B-h",
        parent_id="A",
        votes=tuple(),
    )
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "X": {"prev_block_id": "A"},
        "Y": {"prev_block_id": "X"},
    }
    justify_qc = QuorumCert(
        chain_id="weall:test",
        view=7,
        block_id="X",
        block_hash="X-h",
        parent_id="A",
        votes=tuple(),
    )

    assert bft.can_vote_for(blocks=blocks, block_id="Y", justify_qc=justify_qc) is True
