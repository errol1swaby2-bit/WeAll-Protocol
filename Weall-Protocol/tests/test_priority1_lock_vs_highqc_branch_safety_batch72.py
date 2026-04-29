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


def test_higher_view_conflicting_branch_can_raise_high_qc_without_regressing_lock_batch72() -> None:
    hs = HotStuffBFT(chain_id="batch72")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    hs.locked_qc = _qc("batch72", 4, "B1", "A")
    hs.high_qc = _qc("batch72", 4, "B1", "A")

    hs.observe_qc(blocks=blocks, qc=_qc("batch72", 6, "C2", "B2"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C2"
    assert int(hs.high_qc.view) == 6
    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "B1"
    assert int(hs.locked_qc.view) == 4


def test_descendant_higher_view_qc_advances_both_high_and_locked_qc_batch72() -> None:
    hs = HotStuffBFT(chain_id="batch72")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.locked_qc = _qc("batch72", 3, "B", "A")
    hs.high_qc = _qc("batch72", 3, "B", "A")

    hs.observe_qc(blocks=blocks, qc=_qc("batch72", 5, "D", "C"))

    assert hs.high_qc is not None
    assert hs.locked_qc is not None
    assert hs.high_qc.block_id == "D"
    assert hs.locked_qc.block_id == "D"
    assert int(hs.high_qc.view) == 5
    assert int(hs.locked_qc.view) == 5
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B"


def test_conflicting_higher_view_qc_roundtrip_preserves_split_state_batch72() -> None:
    hs = HotStuffBFT(chain_id="batch72")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    hs.locked_qc = _qc("batch72", 4, "B1", "A")
    hs.high_qc = _qc("batch72", 4, "B1", "A")
    hs.observe_qc(blocks=blocks, qc=_qc("batch72", 6, "C2", "B2"))

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch72")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert hs2.high_qc is not None
    assert hs2.locked_qc is not None
    assert hs2.high_qc.block_id == "C2"
    assert hs2.locked_qc.block_id == "B1"


def test_can_vote_for_uses_locked_branch_not_high_qc_branch_batch72() -> None:
    hs = HotStuffBFT(chain_id="batch72")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    hs.locked_qc = _qc("batch72", 4, "B1", "A")
    hs.high_qc = _qc("batch72", 6, "C2", "B2")

    assert hs.can_vote_for(blocks=blocks, block_id="C1", justify_qc=None) is True
    assert hs.can_vote_for(blocks=blocks, block_id="C2", justify_qc=None) is False
