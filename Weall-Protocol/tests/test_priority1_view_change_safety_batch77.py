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


def test_view_monotonicity_under_qc_observation_batch77() -> None:
    hs = HotStuffBFT(chain_id="batch77")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch77", 5, "B", "A"))
    assert int(hs.view) >= 5

    hs.observe_qc(blocks=blocks, qc=_qc("batch77", 3, "A", ""))
    assert int(hs.view) >= 5


def test_view_progression_after_roundtrip_batch77() -> None:
    hs = HotStuffBFT(chain_id="batch77")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch77", 4, "B", "A"))
    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch77")
    hs2.load_from_state({"bft": state})
    hs2.observe_qc(blocks=blocks, qc=_qc("batch77", 6, "C", "B"))

    assert int(hs2.view) >= 6


def test_stale_qc_does_not_regress_view_after_reload_batch77() -> None:
    hs = HotStuffBFT(chain_id="batch77")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch77", 7, "B", "A"))
    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch77")
    hs2.load_from_state({"bft": state})
    hs2.observe_qc(blocks=blocks, qc=_qc("batch77", 2, "A", ""))

    assert int(hs2.view) >= 7


def test_view_state_roundtrip_consistency_batch77() -> None:
    hs = HotStuffBFT(chain_id="batch77")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch77", 5, "B", "A"))
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch77")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert int(state2.get("view") or 0) >= 5
