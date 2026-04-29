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


def test_finalized_view_never_regresses_under_stale_qc_batch74() -> None:
    hs = HotStuffBFT(chain_id="batch74")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch74", 5, "D", "C"))
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B"

    hs.observe_qc(blocks=blocks, qc=_qc("batch74", 3, "C", "B"))
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B"


def test_finalized_block_id_survives_roundtrip_without_drift_batch74() -> None:
    hs = HotStuffBFT(chain_id="batch74")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch74", 5, "D", "C"))
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch74")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert int(state2.get("finalized_view") or 0) == 5
    assert str(state2.get("finalized_block_id") or "") == "B"


def test_higher_view_same_branch_can_advance_finalized_view_batch74() -> None:
    hs = HotStuffBFT(chain_id="batch74")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
        "E": {"prev_block_id": "D"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch74", 5, "D", "C"))
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B"

    hs.observe_qc(blocks=blocks, qc=_qc("batch74", 6, "E", "D"))
    assert int(hs.finalized_view) == 6
    assert str(hs.finalized_block_id or "") == "C"


def test_conflicting_branch_cannot_regress_finalized_state_batch74() -> None:
    hs = HotStuffBFT(chain_id="batch74")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "D1": {"prev_block_id": "C1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch74", 5, "D1", "C1"))
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B1"

    hs.observe_qc(blocks=blocks, qc=_qc("batch74", 4, "D2", "C2"))
    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B1"
