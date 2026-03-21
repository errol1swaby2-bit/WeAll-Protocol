from __future__ import annotations

from pathlib import Path

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _qc(*, chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def _latest_block_id(ex: WeAllExecutor) -> str:
    latest = ex.get_latest_block()
    if not isinstance(latest, dict):
        return ""
    return str(latest.get("block_id") or "")


def test_finalize_is_idempotent_under_duplicate_qc_batch60() -> None:
    hs = HotStuffBFT(chain_id="batch60")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    qc = _qc(chain_id="batch60", view=4, block_id="C", parent_id="B")

    r1 = hs.observe_qc(blocks=blocks, qc=qc)
    st1 = hs.export_state()

    r2 = hs.observe_qc(blocks=blocks, qc=qc)
    st2 = hs.export_state()

    assert r1 in {"A", None}
    assert r2 is None
    assert st1 == st2
    assert int(st2.get("finalized_view") or 0) == 4
    assert str(st2.get("finalized_block_id") or "") == "A"


def test_finalize_does_not_regress_under_stale_qc_batch60() -> None:
    hs = HotStuffBFT(chain_id="batch60")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
        "D": {"prev_block_id": "C"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch60", view=5, block_id="D", parent_id="C"))
    st1 = hs.export_state()
    assert int(st1.get("finalized_view") or 0) == 5
    assert str(st1.get("finalized_block_id") or "") == "B"

    hs.observe_qc(blocks=blocks, qc=_qc(chain_id="batch60", view=3, block_id="C", parent_id="B"))
    st2 = hs.export_state()
    assert int(st2.get("finalized_view") or 0) == 5
    assert str(st2.get("finalized_block_id") or "") == "B"


def test_executor_height_and_tip_remain_stable_on_empty_production_batch60(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "empty.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch60-empty",
        tx_index_path=tx_index_path,
    )

    st0 = ex.read_state()
    h0 = int(st0.get("height", 0))
    tip0 = _latest_block_id(ex)

    meta1 = ex.produce_block(max_txs=10)
    assert meta1.ok is True

    st1 = ex.read_state()
    h1 = int(st1.get("height", 0))
    tip1 = _latest_block_id(ex)

    meta2 = ex.produce_block(max_txs=10)
    assert meta2.ok is True

    st2 = ex.read_state()
    h2 = int(st2.get("height", 0))
    tip2 = _latest_block_id(ex)

    assert h1 >= h0
    assert h2 >= h1
    if h2 == h1:
        assert tip2 == tip1
    if h1 == h0:
        assert tip1 == tip0


def test_executor_restart_after_empty_production_keeps_canonical_tip_batch60(
    tmp_path: Path,
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "restart-empty.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch60-restart-empty",
        tx_index_path=tx_index_path,
    )

    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    tip1 = _latest_block_id(ex)
    h1 = int(ex.read_state().get("height", 0))

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch60-restart-empty",
        tx_index_path=tx_index_path,
    )
    tip2 = _latest_block_id(ex2)
    h2 = int(ex2.read_state().get("height", 0))

    assert h2 == h1
    assert tip2 == tip1
