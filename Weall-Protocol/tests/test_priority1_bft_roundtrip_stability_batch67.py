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


def test_high_qc_persists_through_multiple_roundtrips_batch67() -> None:
    hs = HotStuffBFT(chain_id="batch67")
    hs.high_qc = _qc("batch67", 7, "B7", "B6")

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch67")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    hs3 = HotStuffBFT(chain_id="batch67")
    hs3.load_from_state({"bft": state2})
    state3 = hs3.export_state()

    assert state1 == state2 == state3
    assert hs3.high_qc is not None
    assert hs3.high_qc.block_id == "B7"
    assert int(hs3.high_qc.view) == 7


def test_locked_qc_persists_through_multiple_roundtrips_batch67() -> None:
    hs = HotStuffBFT(chain_id="batch67")
    hs.locked_qc = _qc("batch67", 5, "L5", "L4")

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch67")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    hs3 = HotStuffBFT(chain_id="batch67")
    hs3.load_from_state({"bft": state2})
    state3 = hs3.export_state()

    assert state1 == state2 == state3
    assert hs3.locked_qc is not None
    assert hs3.locked_qc.block_id == "L5"
    assert int(hs3.locked_qc.view) == 5


def test_finalized_markers_persist_without_drift_batch67() -> None:
    hs = HotStuffBFT(chain_id="batch67")
    hs.finalized_view = 9
    hs.finalized_block_id = "F9"

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch67")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    hs3 = HotStuffBFT(chain_id="batch67")
    hs3.load_from_state({"bft": state2})
    state3 = hs3.export_state()

    assert state1 == state2 == state3
    assert int(state3.get("finalized_view") or 0) == 9
    assert str(state3.get("finalized_block_id") or "") == "F9"


def test_vote_state_persists_without_drift_batch67() -> None:
    hs = HotStuffBFT(chain_id="batch67")
    assert hs.record_local_vote(view=6, block_id="B6") is True

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch67")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    hs3 = HotStuffBFT(chain_id="batch67")
    hs3.load_from_state({"bft": state2})
    state3 = hs3.export_state()

    assert state1 == state2 == state3
    assert int(state3.get("last_voted_view") or 0) == 6
    assert str(state3.get("last_voted_block_id") or "") == "B6"
