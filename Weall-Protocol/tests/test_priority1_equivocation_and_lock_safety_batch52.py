from __future__ import annotations

from pathlib import Path

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def _qc(*, chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def test_same_view_conflicting_vote_is_rejected_batch52() -> None:
    hs = HotStuffBFT(chain_id="batch52")

    assert hs.record_local_vote(view=4, block_id="B4") is True
    assert hs.record_local_vote(view=4, block_id="B4") is True
    assert hs.record_local_vote(view=4, block_id="X4") is False

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 4
    assert str(st.get("last_voted_block_id") or "") == "B4"


def test_lower_view_vote_after_higher_view_vote_is_rejected_batch52() -> None:
    hs = HotStuffBFT(chain_id="batch52")

    assert hs.record_local_vote(view=6, block_id="B6") is True
    assert hs.record_local_vote(view=5, block_id="B5") is False

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 6
    assert str(st.get("last_voted_block_id") or "") == "B6"


def test_locked_branch_blocks_conflicting_qc_progression_batch52() -> None:
    hs = HotStuffBFT(chain_id="batch52")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
        "Y": {"prev_block_id": "X"},
    }

    hs.locked_qc = _qc(chain_id="batch52", view=3, block_id="B", parent_id="A")

    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch52", view=7, block_id="Y", parent_id="X"))
    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "B"
    assert int(hs.locked_qc.view) == 3

    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch52", view=8, block_id="C", parent_id="B"))
    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "C"
    assert int(hs.locked_qc.view) == 8


def test_high_qc_never_regresses_under_stale_observations_batch52() -> None:
    hs = HotStuffBFT(chain_id="batch52")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch52", view=5, block_id="C", parent_id="B"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C"
    assert int(hs.high_qc.view) == 5

    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch52", view=2, block_id="B", parent_id="A"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C"
    assert int(hs.high_qc.view) == 5
