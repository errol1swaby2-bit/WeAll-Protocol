from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_tx_status_prefers_committed_block_over_stale_mempool_batch397() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "tx.py").read_text(encoding="utf-8")
    fn = src.split('@router.get("/tx/status/{tx_id}")', 1)[1].split("_TX_INDEX_JSON_PATH", 1)[0]

    assert "Confirmed chain state is authoritative over stale mempool residency" in fn
    assert "observer reconciliation can prove upstream confirmation" in fn
    assert fn.index("blk = _tx_block_lookup(request, t)") < fn.index("mp = _safe_mempool(request)")
    assert '"status": "pending"' in fn
