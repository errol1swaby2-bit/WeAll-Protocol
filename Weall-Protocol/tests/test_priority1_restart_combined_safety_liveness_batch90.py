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


def test_restart_preserves_timeout_reset_after_progress_batch90() -> None:
    hs = HotStuffBFT(chain_id="batch90")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=1)
    hs.note_timeout_emitted(view=2)
    assert hs.pacemaker_timeout_ms() >= 2000

    hs.note_progress()
    assert hs.pacemaker_timeout_ms() == 1000

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch90")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": state1})

    assert hs2.pacemaker_timeout_ms() == 1000
    assert int(hs2.export_state().get("timeout_backoff_exp") or 0) == 0


def test_restart_preserves_locked_branch_safety_after_conflicting_high_qc_batch90() -> None:
    hs = HotStuffBFT(chain_id="batch90")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "D1": {"prev_block_id": "C1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch90", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch90", 4, "C1", "B1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch90", 5, "D2", "C2"))

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch90")
    hs2.load_from_state({"bft": state1})

    assert hs2.locked_qc is not None
    assert hs2.high_qc is not None
    assert hs2.locked_qc.block_id == "C1"
    assert hs2.high_qc.block_id == "D2"
    assert hs2.can_vote_for(blocks=blocks, block_id="D1", justify_qc=None) is True
    assert hs2.can_vote_for(blocks=blocks, block_id="D2", justify_qc=None) is False


def test_restart_preserves_finalization_and_allows_forward_progress_batch90() -> None:
    hs = HotStuffBFT(chain_id="batch90")
    hs.timeout_base_ms = 1000

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
        "E": {"prev_block_id": "D"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch90", 5, "D", "C"))
    hs.note_progress()

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch90")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": state1})

    assert int(hs2.finalized_view) == 5
    assert str(hs2.finalized_block_id or "") == "B"
    assert hs2.pacemaker_timeout_ms() == 1000

    hs2.observe_qc(blocks=blocks, qc=_qc("batch90", 6, "E", "D"))
    assert int(hs2.finalized_view) == 6
    assert str(hs2.finalized_block_id or "") == "C"
    assert hs2.pacemaker_timeout_ms() == 1000


def test_restart_then_stale_messages_cannot_regress_combined_state_batch90() -> None:
    hs = HotStuffBFT(chain_id="batch90")
    hs.timeout_base_ms = 1000

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.note_timeout_emitted(view=1)
    hs.note_timeout_emitted(view=2)
    hs.observe_qc(blocks=blocks, qc=_qc("batch90", 5, "D", "C"))
    hs.note_progress()

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch90")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": state1})

    hs2.observe_qc(blocks=blocks, qc=_qc("batch90", 3, "B", "A"))

    assert hs2.high_qc is not None
    assert hs2.high_qc.block_id == "D"
    assert int(hs2.high_qc.view) == 5
    assert int(hs2.finalized_view) == 5
    assert str(hs2.finalized_block_id or "") == "B"
    assert hs2.pacemaker_timeout_ms() == 1000
