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


def test_higher_view_qc_wins_fork_choice_batch84() -> None:
    hs = HotStuffBFT(chain_id="batch84")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    # Competing branches
    hs.observe_qc(blocks=blocks, qc=_qc("batch84", 3, "C1", "B1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch84", 4, "C2", "B2"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C2"
    assert int(hs.high_qc.view) == 4


def test_same_view_conflict_does_not_flip_high_qc_batch84() -> None:
    hs = HotStuffBFT(chain_id="batch84")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    qc1 = _qc("batch84", 4, "C1", "B1")
    qc2 = _qc("batch84", 4, "C2", "B2")

    hs.observe_qc(blocks=blocks, qc=qc1)
    first = hs.high_qc

    hs.observe_qc(blocks=blocks, qc=qc2)
    second = hs.high_qc

    # Same view conflict should not arbitrarily flip
    assert first is not None
    assert second is not None
    assert first.view == second.view
    assert first.block_id == second.block_id


def test_descendant_qc_extends_chain_not_replace_with_sibling_batch84() -> None:
    hs = HotStuffBFT(chain_id="batch84")

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
        "C2": {"prev_block_id": "B"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch84", 3, "C", "B"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch84", 4, "D", "C"))

    # Competing sibling arrives later
    hs.observe_qc(blocks=blocks, qc=_qc("batch84", 4, "C2", "B"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "D"


def test_fork_choice_stable_under_reordering_batch84() -> None:
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    qc_low = _qc("batch84", 3, "C1", "B1")
    qc_high = _qc("batch84", 5, "C2", "B2")

    hs1 = HotStuffBFT(chain_id="batch84")
    hs1.observe_qc(blocks=blocks, qc=qc_low)
    hs1.observe_qc(blocks=blocks, qc=qc_high)

    hs2 = HotStuffBFT(chain_id="batch84")
    hs2.observe_qc(blocks=blocks, qc=qc_high)
    hs2.observe_qc(blocks=blocks, qc=qc_low)

    assert hs1.high_qc is not None
    assert hs2.high_qc is not None
    assert hs1.high_qc.block_id == hs2.high_qc.block_id
    assert int(hs1.high_qc.view) == int(hs2.high_qc.view)
