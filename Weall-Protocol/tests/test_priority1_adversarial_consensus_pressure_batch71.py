from __future__ import annotations

from pathlib import Path

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


def test_conflicting_same_view_qcs_do_not_regress_high_qc_batch71() -> None:
    hs = HotStuffBFT(chain_id="batch71")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "B2": {"prev_block_id": "A"},
    }

    qc1 = _qc("batch71", 5, "B1", "A")
    qc2 = _qc("batch71", 5, "B2", "A")

    hs.observe_qc(blocks=blocks, qc=qc1)
    state1 = hs.export_state()

    hs.observe_qc(blocks=blocks, qc=qc2)
    state2 = hs.export_state()

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "B1"
    assert int(hs.high_qc.view) == 5
    assert state1 == state2


def test_reordered_qc_delivery_keeps_highest_valid_qc_batch71() -> None:
    hs = HotStuffBFT(chain_id="batch71")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    # Deliver highest first, then stale
    hs.observe_qc(blocks=blocks, qc=_qc("batch71", 7, "D", "C"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch71", 5, "C", "B"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch71", 3, "B", "A"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "D"
    assert int(hs.high_qc.view) == 7
    assert int(hs.finalized_view) == 7
    assert str(hs.finalized_block_id or "") == "B"


def test_conflicting_same_view_votes_allow_only_first_choice_batch71() -> None:
    hs = HotStuffBFT(chain_id="batch71")

    assert hs.record_local_vote(view=8, block_id="X1") is True
    assert hs.record_local_vote(view=8, block_id="X2") is False

    st = hs.export_state()
    assert int(st.get("last_voted_view") or 0) == 8
    assert str(st.get("last_voted_block_id") or "") == "X1"


def test_qc_roundtrip_after_conflict_attempt_has_no_state_drift_batch71() -> None:
    hs = HotStuffBFT(chain_id="batch71")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "B2": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch71", 4, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch71", 4, "B2", "A"))  # conflicting same-view QC attempt
    hs.observe_qc(blocks=blocks, qc=_qc("batch71", 5, "C1", "B1"))

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch71")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert hs2.high_qc is not None
    assert hs2.high_qc.block_id == "C1"
    assert int(hs2.high_qc.view) == 5
