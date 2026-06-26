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


def test_proposal_must_extend_locked_qc_batch88() -> None:
    hs = HotStuffBFT(chain_id="batch88")

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
        "X": {"prev_block_id": "A"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 3, "B", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 4, "C", "B"))

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "C"

    assert hs.can_vote_for(blocks=blocks, block_id="D", justify_qc=None) is True
    assert hs.can_vote_for(blocks=blocks, block_id="X", justify_qc=None) is False


def test_higher_qc_can_override_locked_qc_batch88() -> None:
    hs = HotStuffBFT(chain_id="batch88")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 4, "C1", "B1"))

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "C1"

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 5, "D2", "C2"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "D2"
    assert int(hs.high_qc.view) == 5

    # A higher conflicting highQC alone does not override the lock for the QC
    # block itself without explicit justify evidence on the proposal.
    assert hs.can_vote_for(blocks=blocks, block_id="D2", justify_qc=None) is False


def test_equal_view_conflicting_qc_does_not_override_lock_batch88() -> None:
    hs = HotStuffBFT(chain_id="batch88")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 4, "C1", "B1"))

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "C1"

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 4, "C2", "B2"))

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "C1"
    assert hs.can_vote_for(blocks=blocks, block_id="C2", justify_qc=None) is False


def test_locked_qc_persists_across_restart_batch88() -> None:
    hs = HotStuffBFT(chain_id="batch88")

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 3, "B", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 4, "C", "B"))

    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch88")
    hs2.load_from_state({"bft": state})

    assert hs2.locked_qc is not None
    assert hs2.locked_qc.block_id == "C"
    assert hs2.can_vote_for(blocks=blocks, block_id="D", justify_qc=None) is True


def test_local_high_qc_allows_descendant_recovery_child_batch88() -> None:
    hs = HotStuffBFT(chain_id="batch88")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
        "E2": {"prev_block_id": "D2"},
        "Y": {"prev_block_id": "A"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 4, "C1", "B1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 5, "D2", "C2"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "D2"
    assert hs.can_vote_for(blocks=blocks, block_id="D2", justify_qc=None) is False
    assert hs.can_vote_for(blocks=blocks, block_id="E2", justify_qc=None) is True
    assert hs.can_vote_for(blocks=blocks, block_id="Y", justify_qc=None) is False


def test_local_high_qc_descendant_recovery_survives_restart_batch88() -> None:
    hs = HotStuffBFT(chain_id="batch88")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
        "E2": {"prev_block_id": "D2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 4, "C1", "B1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch88", 5, "D2", "C2"))

    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch88")
    hs2.load_from_state({"bft": state})

    assert hs2.high_qc is not None
    assert hs2.high_qc.block_id == "D2"
    assert hs2.locked_qc is not None
    assert hs2.locked_qc.block_id == "C1"
    assert hs2.can_vote_for(blocks=blocks, block_id="D2", justify_qc=None) is False
    assert hs2.can_vote_for(blocks=blocks, block_id="E2", justify_qc=None) is True
