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


def test_high_qc_advances_monotonically_across_roundtrips_batch75() -> None:
    hs = HotStuffBFT(chain_id="batch75")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch75", 3, "B", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch75", 4, "C", "B"))

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch75")
    hs2.load_from_state({"bft": state1})
    hs2.observe_qc(blocks=blocks, qc=_qc("batch75", 5, "D", "C"))

    state2 = hs2.export_state()

    assert hs2.high_qc is not None
    assert hs2.high_qc.block_id == "D"
    assert int(hs2.high_qc.view) == 5
    assert int(state2.get("view") or 0) >= int(state1.get("view") or 0)


def test_locked_qc_never_regresses_after_roundtrip_batch75() -> None:
    hs = HotStuffBFT(chain_id="batch75")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    hs.locked_qc = _qc("batch75", 4, "B", "A")
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch75")
    hs2.load_from_state({"bft": state1})
    hs2.observe_qc(blocks=blocks, qc=_qc("batch75", 3, "A", ""))

    assert hs2.locked_qc is not None
    assert hs2.locked_qc.block_id == "B"
    assert int(hs2.locked_qc.view) == 4


def test_descendant_qc_after_roundtrip_advances_lock_batch75() -> None:
    hs = HotStuffBFT(chain_id="batch75")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.locked_qc = _qc("batch75", 3, "B", "A")
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch75")
    hs2.load_from_state({"bft": state1})
    hs2.observe_qc(blocks=blocks, qc=_qc("batch75", 5, "D", "C"))

    assert hs2.locked_qc is not None
    assert hs2.locked_qc.block_id == "D"
    assert int(hs2.locked_qc.view) == 5


def test_high_qc_and_locked_qc_split_state_survives_roundtrip_batch75() -> None:
    hs = HotStuffBFT(chain_id="batch75")
    hs.locked_qc = _qc("batch75", 4, "B1", "A")
    hs.high_qc = _qc("batch75", 6, "C2", "B2")
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch75")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert hs2.high_qc is not None
    assert hs2.locked_qc is not None
    assert hs2.high_qc.block_id == "C2"
    assert hs2.locked_qc.block_id == "B1"
