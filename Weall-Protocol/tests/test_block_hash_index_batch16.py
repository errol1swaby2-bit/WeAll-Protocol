from __future__ import annotations

import copy
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, *, chain_id: str = "batch16") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _commit_empty_block(ex: WeAllExecutor, *, ts_ms: int = 1000) -> dict:
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=ts_ms
    )
    assert err == ""
    assert isinstance(blk, dict)
    assert isinstance(st2, dict)
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    assert meta.ok is True
    return blk


def test_block_hash_sidecar_index_persists_across_restart(tmp_path: Path) -> None:
    ex = _make_executor(tmp_path, "node")
    blk = _commit_empty_block(ex, ts_ms=1000)
    bid = str(blk["block_id"])
    bh = str(blk["block_hash"])

    restarted = _make_executor(tmp_path, "node")
    assert restarted._known_block_hash_for_id(bid) == bh

    with restarted._db.connection() as con:
        row = con.execute(
            "SELECT block_hash, height FROM block_hash_index WHERE block_id=? LIMIT 1;",
            (bid,),
        ).fetchone()
    assert row is not None
    assert str(row["block_hash"] or "") == bh
    assert int(row["height"] or 0) == 1


def test_block_identity_conflict_uses_sidecar_index_without_block_scan(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, "node", chain_id="batch16-conflict")
    blk = _commit_empty_block(ex, ts_ms=1000)
    bid = str(blk["block_id"])

    restarted = _make_executor(tmp_path, "node", chain_id="batch16-conflict")

    def _boom(_block_id: str):
        raise AssertionError("should not scan blocks table when sidecar index is present")

    monkeypatch.setattr(restarted, "get_block_by_id", _boom)

    forged = copy.deepcopy(blk)
    forged.pop("block_hash", None)
    forged["header"] = dict(forged.get("header") or {})
    forged["header"]["state_root"] = "ff" * 32

    meta = restarted.apply_block(forged)
    assert meta.ok is False
    assert meta.error == "bad_block:block_id_hash_conflict"
    diag = restarted.bft_diagnostics()
    assert bid in diag["conflicted_block_ids"]
