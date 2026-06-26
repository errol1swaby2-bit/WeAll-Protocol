from __future__ import annotations

from pathlib import Path

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_local_vote_is_monotonic_and_non_equivocating_batch43() -> None:
    bft = HotStuffBFT(chain_id="batch43")

    assert bft.record_local_vote(view=1, block_id="B1") is True
    assert bft.record_local_vote(view=1, block_id="B1") is True
    assert bft.record_local_vote(view=1, block_id="B2") is False
    assert bft.record_local_vote(view=0, block_id="B0") is False
    assert bft.record_local_vote(view=2, block_id="B2") is True


def test_locked_qc_does_not_move_to_conflicting_branch_batch43() -> None:
    bft = HotStuffBFT(chain_id="batch43")

    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "X": {"prev_block_id": "A"},
    }

    bft.locked_qc = QuorumCert(
        chain_id="batch43",
        view=1,
        block_id="B",
        block_hash="B-h",
        parent_id="A",
        votes=tuple(),
    )

    qc_x = QuorumCert(
        chain_id="batch43",
        view=9,
        block_id="X",
        block_hash="X-h",
        parent_id="A",
        votes=tuple(),
    )
    bft.observe_qc(blocks=blocks, qc=qc_x)
    assert bft.locked_qc is not None
    assert bft.locked_qc.block_id == "B"

    qc_c = QuorumCert(
        chain_id="batch43",
        view=10,
        block_id="C",
        block_hash="C-h",
        parent_id="B",
        votes=tuple(),
    )
    bft.observe_qc(blocks=blocks, qc=qc_c)
    assert bft.locked_qc is not None
    assert bft.locked_qc.block_id == "C"


def test_executor_bft_set_view_is_monotonic_across_restart(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "node.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch43-view",
        tx_index_path=tx_index_path,
    )

    ex.bft_set_view(2)
    assert int(ex.state.get("bft", {}).get("view") or 0) == 2

    ex.bft_set_view(1)
    assert int(ex.state.get("bft", {}).get("view") or 0) == 2

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch43-view",
        tx_index_path=tx_index_path,
    )
    assert int(ex2.state.get("bft", {}).get("view") or 0) == 2

    ex2.bft_set_view(5)
    assert int(ex2.state.get("bft", {}).get("view") or 0) == 5

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch43-view",
        tx_index_path=tx_index_path,
    )
    assert int(ex3.state.get("bft", {}).get("view") or 0) == 5
