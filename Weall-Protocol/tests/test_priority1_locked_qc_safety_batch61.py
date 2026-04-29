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


def test_locked_qc_prevents_conflicting_vote_batch61() -> None:
    hs = HotStuffBFT(chain_id="batch61")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
    }

    hs.locked_qc = _qc("batch61", 5, "B", "A")

    # Conflicting branch must be rejected by the ancestry-aware safety gate.
    assert hs.can_vote_for(blocks=blocks, block_id="X", justify_qc=None) is False
    # Descendant of the locked branch remains allowed.
    assert hs.can_vote_for(blocks=blocks, block_id="C", justify_qc=None) is True


def test_locked_qc_persists_across_reload_batch61() -> None:
    hs = HotStuffBFT(chain_id="batch61")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
    }
    hs.locked_qc = _qc("batch61", 5, "B", "A")

    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch61")
    hs2.load_from_state({"bft": state})

    assert hs2.locked_qc is not None
    assert hs2.locked_qc.block_id == "B"
    assert int(hs2.locked_qc.view) == 5

    # Conflict still rejected after reload.
    assert hs2.can_vote_for(blocks=blocks, block_id="X", justify_qc=None) is False
    assert hs2.can_vote_for(blocks=blocks, block_id="C", justify_qc=None) is True


def test_locked_qc_updates_only_forward_batch61() -> None:
    hs = HotStuffBFT(chain_id="batch61")

    hs.locked_qc = _qc("batch61", 4, "A", "")

    hs.observe_qc(
        blocks={"A": {"prev_block_id": ""}, "B": {"prev_block_id": "A"}},
        qc=_qc("batch61", 5, "B", "A"),
    )

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "B"
    assert int(hs.locked_qc.view) == 5

    hs.observe_qc(
        blocks={"A": {"prev_block_id": ""}, "B": {"prev_block_id": "A"}},
        qc=_qc("batch61", 3, "A", ""),
    )

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "B"
    assert int(hs.locked_qc.view) == 5
