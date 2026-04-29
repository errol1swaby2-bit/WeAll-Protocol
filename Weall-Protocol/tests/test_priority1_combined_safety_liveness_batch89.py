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


def test_stale_qc_cannot_break_liveness_progress_batch89() -> None:
    hs = HotStuffBFT(chain_id="batch89")
    hs.timeout_base_ms = 1000

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.note_timeout_emitted(view=1)
    hs.note_timeout_emitted(view=2)
    grown = hs.pacemaker_timeout_ms()
    assert grown >= 2000

    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 5, "D", "C"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "D"
    assert int(hs.high_qc.view) == 5

    hs.note_progress()
    assert hs.pacemaker_timeout_ms() == 1000

    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 3, "B", "A"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "D"
    assert int(hs.high_qc.view) == 5
    assert hs.pacemaker_timeout_ms() == 1000


def test_conflicting_branch_does_not_break_locked_branch_vote_safety_batch89() -> None:
    hs = HotStuffBFT(chain_id="batch89")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "D1": {"prev_block_id": "C1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 4, "C1", "B1"))

    assert hs.locked_qc is not None
    locked_before = hs.locked_qc.block_id

    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 5, "D2", "C2"))

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == locked_before
    assert hs.can_vote_for(blocks=blocks, block_id="D1", justify_qc=None) is True
    assert hs.can_vote_for(blocks=blocks, block_id="D2", justify_qc=None) is False


def test_progress_then_roundtrip_preserves_safety_and_liveness_state_batch89() -> None:
    hs = HotStuffBFT(chain_id="batch89")
    hs.timeout_base_ms = 1000

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.note_timeout_emitted(view=1)
    hs.note_timeout_emitted(view=2)
    assert hs.pacemaker_timeout_ms() >= 2000

    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 5, "D", "C"))
    hs.note_progress()

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch89")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert hs2.high_qc is not None
    assert hs2.high_qc.block_id == "D"
    assert int(hs2.high_qc.view) == 5
    assert hs2.pacemaker_timeout_ms() == 1000


def test_finalization_and_timeout_reset_can_coexist_without_regression_batch89() -> None:
    hs = HotStuffBFT(chain_id="batch89")
    hs.timeout_base_ms = 1000

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
        "E": {"prev_block_id": "D"},
    }

    hs.note_timeout_emitted(view=1)
    hs.note_timeout_emitted(view=2)
    assert hs.pacemaker_timeout_ms() >= 2000

    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 5, "D", "C"))
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B"

    hs.note_progress()
    assert hs.pacemaker_timeout_ms() == 1000

    hs.observe_qc(blocks=blocks, qc=_qc("batch89", 6, "E", "D"))
    assert int(hs.finalized_view) == 6
    assert str(hs.finalized_block_id or "") == "C"
    assert hs.pacemaker_timeout_ms() == 1000
