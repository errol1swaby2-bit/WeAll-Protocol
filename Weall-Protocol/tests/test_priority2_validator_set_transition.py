from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def _qc(view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id="batch111",
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
        validator_epoch=1,
        validator_set_hash="set-a",
    )


def test_validator_set_transition_safe_batch111() -> None:
    hs = HotStuffBFT(chain_id="batch111")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    assert hs.observe_qc(blocks=blocks, qc=_qc(1, "A", "")) is None
    assert hs.observe_qc(blocks=blocks, qc=_qc(2, "B", "A")) is None
    finalized = hs.observe_qc(blocks=blocks, qc=_qc(3, "C", "B"))

    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C"
    assert finalized == "A"
