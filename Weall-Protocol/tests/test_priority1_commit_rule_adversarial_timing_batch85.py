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


def test_higher_conflicting_qc_does_not_retroactively_change_committed_block_batch85() -> None:
    hs = HotStuffBFT(chain_id="batch85")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "D1": {"prev_block_id": "C1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 4, "C1", "B1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 5, "D1", "C1"))

    assert int(hs.finalized_view) == 5
    assert str(hs.finalized_block_id or "") == "B1"

    # Later conflicting branch with higher QC must not rewrite committed history.
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 6, "D2", "C2"))

    assert int(hs.finalized_view) >= 5
    assert str(hs.finalized_block_id or "") == "B1"


def test_reordered_three_chain_delivery_keeps_same_finalized_block_batch85() -> None:
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs1 = HotStuffBFT(chain_id="batch85")
    hs1.observe_qc(blocks=blocks, qc=_qc("batch85", 3, "B", "A"))
    hs1.observe_qc(blocks=blocks, qc=_qc("batch85", 4, "C", "B"))
    hs1.observe_qc(blocks=blocks, qc=_qc("batch85", 5, "D", "C"))

    hs2 = HotStuffBFT(chain_id="batch85")
    hs2.observe_qc(blocks=blocks, qc=_qc("batch85", 5, "D", "C"))
    hs2.observe_qc(blocks=blocks, qc=_qc("batch85", 3, "B", "A"))
    hs2.observe_qc(blocks=blocks, qc=_qc("batch85", 4, "C", "B"))

    assert str(hs1.finalized_block_id or "") == str(hs2.finalized_block_id or "")
    assert int(hs1.finalized_view) == int(hs2.finalized_view)


def test_same_view_conflicting_branches_do_not_create_two_commits_batch85() -> None:
    hs = HotStuffBFT(chain_id="batch85")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "D1": {"prev_block_id": "C1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 4, "C1", "B1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 5, "D1", "C1"))

    committed = str(hs.finalized_block_id or "")
    committed_view = int(hs.finalized_view)

    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 5, "D2", "C2"))

    assert str(hs.finalized_block_id or "") == committed
    assert int(hs.finalized_view) == committed_view


def test_commit_state_roundtrip_after_adversarial_fork_timing_batch85() -> None:
    hs = HotStuffBFT(chain_id="batch85")

    blocks = {
        "A": {"prev_block_id": ""},
        "B1": {"prev_block_id": "A"},
        "C1": {"prev_block_id": "B1"},
        "D1": {"prev_block_id": "C1"},
        "B2": {"prev_block_id": "A"},
        "C2": {"prev_block_id": "B2"},
        "D2": {"prev_block_id": "C2"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 3, "B1", "A"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 4, "C1", "B1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 5, "D1", "C1"))
    hs.observe_qc(blocks=blocks, qc=_qc("batch85", 6, "D2", "C2"))

    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch85")
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert str(hs2.finalized_block_id or "") == "B1"
    assert int(hs2.finalized_view) >= 5
