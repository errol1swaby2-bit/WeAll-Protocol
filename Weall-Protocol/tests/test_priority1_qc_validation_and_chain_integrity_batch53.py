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


def test_qc_with_unknown_parent_is_ignored_batch53() -> None:
    hs = HotStuffBFT(chain_id="b53")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("b53", 3, "X", "Z"))
    assert hs.high_qc is None


def test_qc_chain_progression_requires_parent_link_batch53() -> None:
    hs = HotStuffBFT(chain_id="b53")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("b53", 2, "B", "A"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "B"

    hs.observe_qc(blocks=blocks, qc=_qc("b53", 3, "C", "A"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "B"
    assert int(hs.high_qc.view) == 2


def test_can_vote_for_rejects_if_locked_branch_conflicts_batch53() -> None:
    hs = HotStuffBFT(chain_id="b53")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
    }

    hs.locked_qc = _qc("b53", 5, "B", "A")

    assert hs.can_vote_for(blocks=blocks, block_id="X", justify_qc=None) is False
    assert hs.can_vote_for(blocks=blocks, block_id="C", justify_qc=None) is True


def test_high_qc_updates_only_on_strictly_higher_view_batch53() -> None:
    hs = HotStuffBFT(chain_id="b53")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("b53", 4, "B", "A"))
    assert hs.high_qc is not None
    assert int(hs.high_qc.view) == 4

    hs.observe_qc(blocks=blocks, qc=_qc("b53", 4, "B", "A"))
    assert hs.high_qc is not None
    assert int(hs.high_qc.view) == 4

    hs.observe_qc(blocks=blocks, qc=_qc("b53", 2, "B", "A"))
    assert hs.high_qc is not None
    assert int(hs.high_qc.view) == 4


def test_same_view_conflicting_vote_is_rejected_batch53() -> None:
    hs = HotStuffBFT(chain_id="b53")

    assert hs.record_local_vote(view=4, block_id="B4") is True
    assert hs.record_local_vote(view=4, block_id="B4") is True
    assert hs.record_local_vote(view=4, block_id="X4") is False

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 4
    assert str(st.get("last_voted_block_id") or "") == "B4"
