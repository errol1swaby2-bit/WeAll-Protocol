from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def _qc(chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def test_observed_qc_finalizes_grandparent_when_chain_links_exist_batch73() -> None:
    hs = HotStuffBFT(chain_id="batch73")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch73", 5, "D", "C"))

    # Current implementation finalizes the grandparent of the observed QC block
    # as long as the structural links D -> C -> B exist.
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B"


def test_conflicting_branch_observation_finalizes_its_own_grandparent_batch73() -> None:
    hs = HotStuffBFT(chain_id="batch73")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch73", 3, "C1", "B1"))
    # On the conflicting branch, observing QC for D2 finalizes grandparent B2.
    hs.observe_qc(blocks=blocks, qc=_qc("batch73", 4, "D2", "C2"))

    assert int(hs.finalized_view) == 4
    assert str(hs.finalized_block_id or "") == "B2"


def test_three_chain_commit_rule_only_finalizes_grandparent_batch73() -> None:
    hs = HotStuffBFT(chain_id="batch73")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch73", 3, "B", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch73", 4, "C", "B"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch73", 5, "D", "C"))

    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B"


def test_commit_rule_roundtrip_stability_batch73() -> None:
    hs = HotStuffBFT(chain_id="batch73")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch73", 5, "D", "C"))

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch73")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert hs2.finalized_block_id == "B"
