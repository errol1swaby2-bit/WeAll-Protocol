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


def test_observe_qc_raises_high_qc_monotonically_batch46() -> None:
    hs = HotStuffBFT(chain_id="batch46")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    qc_b = _qc(chain_id="batch46", view=2, block_id="B", parent_id="A")
    qc_c = _qc(chain_id="batch46", view=5, block_id="C", parent_id="B")
    qc_old = _qc(chain_id="batch46", view=1, block_id="A", parent_id="")

    hs.observe_qc(blocks=blocks, qc=qc_b)
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "B"
    assert int(hs.high_qc.view) == 2

    hs.observe_qc(blocks=blocks, qc=qc_c)
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C"
    assert int(hs.high_qc.view) == 5

    hs.observe_qc(blocks=blocks, qc=qc_old)
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C"
    assert int(hs.high_qc.view) == 5


def test_locked_qc_stays_on_descendant_path_only_batch46() -> None:
    hs = HotStuffBFT(chain_id="batch46")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
        "Y": {"prev_block_id": "X"},
    }

    hs.locked_qc = _qc(chain_id="batch46", view=3, block_id="B", parent_id="A")

    qc_y = _qc(chain_id="batch46", view=7, block_id="Y", parent_id="X")
    hs.observe_qc(blocks=blocks, qc=qc_y)
    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "B"
    assert int(hs.locked_qc.view) == 3

    qc_c = _qc(chain_id="batch46", view=8, block_id="C", parent_id="B")
    hs.observe_qc(blocks=blocks, qc=qc_c)
    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "C"
    assert int(hs.locked_qc.view) == 8


def test_high_qc_and_locked_qc_progression_survive_reload_batch46() -> None:
    hs = HotStuffBFT(chain_id="batch46")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch46", view=2, block_id="B", parent_id="A"))
    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch46", view=3, block_id="C", parent_id="B"))

    exported = hs.export_state()
    hs2 = HotStuffBFT(chain_id="batch46")
    hs2.load_from_state({"bft": exported})

    assert hs2.high_qc is not None
    assert hs2.locked_qc is not None
    assert hs2.high_qc.block_id == "C"
    assert hs2.locked_qc.block_id == "C"

    hs2.observe_qc(blocks=blocks, qc=_qc(chain_id="batch46", view=4, block_id="D", parent_id="C"))
    assert hs2.high_qc is not None
    assert hs2.locked_qc is not None
    assert hs2.high_qc.block_id == "D"
    assert hs2.locked_qc.block_id == "D"

    hs3 = HotStuffBFT(chain_id="batch46")
    hs3.load_from_state({"bft": hs2.export_state()})
    assert hs3.high_qc is not None
    assert hs3.locked_qc is not None
    assert hs3.high_qc.block_id == "D"
    assert hs3.locked_qc.block_id == "D"


def test_finalized_markers_remain_monotonic_across_reloads_batch46() -> None:
    hs = HotStuffBFT(chain_id="batch46")
    hs.finalized_view = 10
    hs.finalized_block_id = "F10"

    hs2 = HotStuffBFT(chain_id="batch46")
    hs2.load_from_state({"bft": hs.export_state()})
    assert int(hs2.finalized_view) == 10
    assert hs2.finalized_block_id == "F10"

    hs2.finalized_view = max(int(hs2.finalized_view), 12)
    hs2.finalized_block_id = "F12"

    hs3 = HotStuffBFT(chain_id="batch46")
    hs3.load_from_state({"bft": hs2.export_state()})
    assert int(hs3.finalized_view) == 12
    assert hs3.finalized_block_id == "F12"

    hs3.finalized_view = max(int(hs3.finalized_view), 12)
    hs3.finalized_block_id = "F12"

    hs4 = HotStuffBFT(chain_id="batch46")
    hs4.load_from_state({"bft": hs3.export_state()})
    assert int(hs4.finalized_view) == 12
    assert hs4.finalized_block_id == "F12"
