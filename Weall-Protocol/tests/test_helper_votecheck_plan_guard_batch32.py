from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.runtime.parallel_execution import canonical_helper_execution_plan_fingerprint


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_votecheck_static_rejects_helper_plan_id_mismatch_batch32(tmp_path: Path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "votecheck.db"),
        node_id="@n1",
        chain_id="c1",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    lanes = [{"lane_id": "L1", "helper_id": "h1", "tx_ids": ["t1"], "descriptor_hash": "d1", "plan_id": "wrong"}]
    blk = {
        "block_id": "b1",
        "prev_block_id": "",
        "header": {"chain_id": "c1", "height": 1},
        "txs": [],
        "helper_execution": {"enabled": True, "plan_id": canonical_helper_execution_plan_fingerprint(lanes), "lanes": lanes},
    }
    assert ex._proposal_votecheck_static_ok(blk) is False
