from __future__ import annotations

from pathlib import Path

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _qc(chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def test_timeout_backoff_does_not_regress_after_reload_batch54() -> None:
    hs = HotStuffBFT(chain_id="batch54")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=1)
    hs.note_timeout_emitted(view=2)
    assert hs.pacemaker_timeout_ms() == 4000

    hs2 = HotStuffBFT(chain_id="batch54")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": hs.export_state()})
    assert hs2.pacemaker_timeout_ms() == 4000

    hs2.note_timeout_emitted(view=3)
    assert hs2.pacemaker_timeout_ms() == 8000

    hs3 = HotStuffBFT(chain_id="batch54")
    hs3.timeout_base_ms = 1000
    hs3.load_from_state({"bft": hs2.export_state()})
    assert hs3.pacemaker_timeout_ms() == 8000
    assert int(hs3.export_state().get("last_timeout_view") or 0) == 3


def test_progress_then_reload_keeps_reset_backoff_batch54() -> None:
    hs = HotStuffBFT(chain_id="batch54")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=4)
    hs.note_timeout_emitted(view=5)
    assert hs.pacemaker_timeout_ms() == 4000

    hs.note_progress()
    assert hs.pacemaker_timeout_ms() == 1000

    hs2 = HotStuffBFT(chain_id="batch54")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": hs.export_state()})
    assert hs2.pacemaker_timeout_ms() == 1000
    assert int(hs2.export_state().get("timeout_backoff_exp", 99)) == 0


def test_bft_view_persistence_remains_monotonic_across_executor_reloads_batch54(
    tmp_path: Path,
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "view.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch54-view",
        tx_index_path=tx_index_path,
    )
    ex.bft_set_view(3)
    assert int(ex.read_state().get("bft", {}).get("view") or 0) == 3

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch54-view",
        tx_index_path=tx_index_path,
    )
    assert int(ex2.read_state().get("bft", {}).get("view") or 0) == 3

    ex2.bft_set_view(2)
    assert int(ex2.read_state().get("bft", {}).get("view") or 0) == 3

    ex2.bft_set_view(5)
    assert int(ex2.read_state().get("bft", {}).get("view") or 0) == 5

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch54-view",
        tx_index_path=tx_index_path,
    )
    assert int(ex3.read_state().get("bft", {}).get("view") or 0) == 5


def test_structurally_invalid_qc_never_updates_high_qc_batch54() -> None:
    hs = HotStuffBFT(chain_id="batch54")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch54", 2, "B", "A"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "B"
    assert int(hs.high_qc.view) == 2

    # Unknown block
    hs.observe_qc(blocks=blocks, qc=_qc("batch54", 5, "X", "Z"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "B"
    assert int(hs.high_qc.view) == 2

    # Known block but wrong parent link
    hs.observe_qc(blocks=blocks, qc=_qc("batch54", 6, "C", "A"))
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "B"
    assert int(hs.high_qc.view) == 2
