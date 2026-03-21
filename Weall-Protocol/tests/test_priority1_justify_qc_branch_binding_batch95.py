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


def test_higher_view_justify_qc_must_anchor_candidate_branch_batch95() -> None:
    hs = HotStuffBFT(chain_id="batch95")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
        "Y": {"prev_block_id": "X"},
        "Z": {"prev_block_id": "A"},
    }

    hs.locked_qc = _qc("batch95", 5, "B", "A")
    justify_qc = _qc("batch95", 7, "X", "A")

    assert hs.can_vote_for(blocks=blocks, block_id="Y", justify_qc=justify_qc) is True
    assert hs.can_vote_for(blocks=blocks, block_id="Z", justify_qc=justify_qc) is False


def test_local_high_qc_recovery_requires_strict_descendant_batch95() -> None:
    hs = HotStuffBFT(chain_id="batch95")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.locked_qc = _qc("batch95", 4, "B1", "A")
    hs.high_qc = _qc("batch95", 6, "C2", "B2")

    assert hs.can_vote_for(blocks=blocks, block_id="C2", justify_qc=None) is False
    assert hs.can_vote_for(blocks=blocks, block_id="D2", justify_qc=None) is True


def test_explicit_stale_justify_cannot_bypass_lock_batch95() -> None:
    hs = HotStuffBFT(chain_id="batch95")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    hs.locked_qc = _qc("batch95", 5, "C1", "B1")
    justify_qc = _qc("batch95", 4, "B2", "A")

    assert hs.can_vote_for(blocks=blocks, block_id="C2", justify_qc=justify_qc) is False


def test_explicit_descendant_justify_on_locked_branch_still_allowed_batch95() -> None:
    hs = HotStuffBFT(chain_id="batch95")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.locked_qc = _qc("batch95", 4, "B", "A")
    justify_qc = _qc("batch95", 4, "C", "B")

    assert hs.can_vote_for(blocks=blocks, block_id="D", justify_qc=justify_qc) is True
