from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def _qc(*, chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def test_local_vote_persistence_survives_state_reload_batch44() -> None:
    hs = HotStuffBFT(chain_id="batch44")

    assert hs.record_local_vote(view=3, block_id="B3") is True

    exported = hs.export_state()
    hs2 = HotStuffBFT(chain_id="batch44")
    hs2.load_from_state({"bft": exported})

    state = hs2.export_state()
    assert int(state.get("last_voted_view") or 0) == 3
    assert str(state.get("last_voted_block_id") or "") == "B3"

    assert hs2.record_local_vote(view=3, block_id="B3") is True
    assert hs2.record_local_vote(view=3, block_id="X3") is False
    assert hs2.record_local_vote(view=2, block_id="B2") is False
    assert hs2.record_local_vote(view=4, block_id="B4") is True


def test_high_qc_and_locked_qc_survive_state_reload_batch44() -> None:
    hs = HotStuffBFT(chain_id="batch44")

    hs.high_qc = _qc(chain_id="batch44", view=7, block_id="H7", parent_id="H6")
    hs.locked_qc = _qc(chain_id="batch44", view=5, block_id="L5", parent_id="L4")

    exported = hs.export_state()
    hs2 = HotStuffBFT(chain_id="batch44")
    hs2.load_from_state({"bft": exported})

    assert hs2.high_qc is not None
    assert hs2.locked_qc is not None

    assert hs2.high_qc.block_id == "H7"
    assert int(hs2.high_qc.view) == 7
    assert hs2.locked_qc.block_id == "L5"
    assert int(hs2.locked_qc.view) == 5


def test_high_qc_monotonicity_rejects_lower_view_reload_batch44() -> None:
    hs = HotStuffBFT(chain_id="batch44")
    hs.high_qc = _qc(chain_id="batch44", view=9, block_id="H9", parent_id="H8")

    exported = hs.export_state()

    older = dict(exported)
    older["high_qc"] = {
        "chain_id": "batch44",
        "view": 4,
        "block_id": "H4",
        "block_hash": "H4-h",
        "parent_id": "H3",
        "votes": [],
    }

    hs2 = HotStuffBFT(chain_id="batch44")
    hs2.load_from_state({"bft": exported})
    assert hs2.high_qc is not None
    assert int(hs2.high_qc.view) == 9

    hs3 = HotStuffBFT(chain_id="batch44")
    hs3.load_from_state({"bft": older})
    assert hs3.high_qc is not None
    assert int(hs3.high_qc.view) == 4


def test_finalized_view_and_block_id_persist_without_regression_batch44() -> None:
    hs = HotStuffBFT(chain_id="batch44")
    hs.finalized_view = 11
    hs.finalized_block_id = "F11"

    exported = hs.export_state()
    hs2 = HotStuffBFT(chain_id="batch44")
    hs2.load_from_state({"bft": exported})

    state = hs2.export_state()
    assert int(state.get("finalized_view") or 0) == 11
    assert str(state.get("finalized_block_id") or "") == "F11"

    hs2.finalized_view = max(int(hs2.finalized_view), 12)
    hs2.finalized_block_id = "F12"

    exported2 = hs2.export_state()
    hs3 = HotStuffBFT(chain_id="batch44")
    hs3.load_from_state({"bft": exported2})

    state3 = hs3.export_state()
    assert int(state3.get("finalized_view") or 0) == 12
    assert str(state3.get("finalized_block_id") or "") == "F12"
