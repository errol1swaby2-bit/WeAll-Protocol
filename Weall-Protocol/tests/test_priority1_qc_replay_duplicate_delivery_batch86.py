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


def test_duplicate_qc_delivery_is_idempotent_batch86() -> None:
    hs = HotStuffBFT(chain_id="batch86")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    qc = _qc("batch86", 4, "C", "B")

    hs.observe_qc(blocks=blocks, qc=qc)
    state1 = hs.export_state()

    hs.observe_qc(blocks=blocks, qc=qc)
    state2 = hs.export_state()

    assert state1 == state2
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C"
    assert int(hs.high_qc.view) == 4


def test_qc_replay_after_roundtrip_is_idempotent_batch86() -> None:
    hs = HotStuffBFT(chain_id="batch86")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    qc = _qc("batch86", 4, "C", "B")
    hs.observe_qc(blocks=blocks, qc=qc)
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch86")
    hs2.load_from_state({"bft": state1})
    hs2.observe_qc(blocks=blocks, qc=qc)
    state2 = hs2.export_state()

    assert state1 == state2
    assert hs2.high_qc is not None
    assert hs2.high_qc.block_id == "C"
    assert int(hs2.high_qc.view) == 4


def test_duplicate_stale_qc_delivery_cannot_regress_state_batch86() -> None:
    hs = HotStuffBFT(chain_id="batch86")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch86", 5, "D", "C"))
    state1 = hs.export_state()

    stale = _qc("batch86", 3, "B", "A")
    hs.observe_qc(blocks=blocks, qc=stale)
    hs.observe_qc(blocks=blocks, qc=stale)
    state2 = hs.export_state()

    assert state1 == state2
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "D"
    assert int(hs.high_qc.view) == 5


def test_duplicate_conflicting_same_view_qcs_do_not_flip_choice_batch86() -> None:
    hs = HotStuffBFT(chain_id="batch86")
    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
    }

    qc1 = _qc("batch86", 4, "C1", "B1")
    qc2 = _qc("batch86", 4, "C2", "B2")

    hs.observe_qc(blocks=blocks, qc=qc1)
    state1 = hs.export_state()

    hs.observe_qc(blocks=blocks, qc=qc2)
    hs.observe_qc(blocks=blocks, qc=qc2)
    state2 = hs.export_state()

    assert state1 == state2
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C1"
    assert int(hs.high_qc.view) == 4
