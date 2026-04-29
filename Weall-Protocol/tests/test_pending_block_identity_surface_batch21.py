from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_pending_block_lookup_by_hash_and_identity_descriptors(tmp_path: Path) -> None:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@u1",
            "nonce": 1,
            "payload": {"pubkey": "k:@u1"},
        }
    )
    assert sub["ok"] is True

    block, _staged, _applied, _invalid, err = ex.build_block_candidate(max_txs=1, force_ts_ms=1000)
    assert err == ""
    assert isinstance(block, dict)

    assert ex.bft_cache_remote_block(dict(block)) is True
    bh = str(block.get("block_hash") or "")
    bid = str(block.get("block_id") or "")

    by_hash = ex._bft_pending_block_json_by_hash(bh)
    assert isinstance(by_hash, dict)
    assert str(by_hash.get("block_id") or "") == bid

    resolved_bid, resolved_blk = ex._resolve_pending_block_identity(block_hash=bh)
    assert resolved_bid == bid
    assert isinstance(resolved_blk, dict)
    assert str(resolved_blk.get("block_hash") or "") == bh

    diag = ex.bft_diagnostics()
    descriptors = diag.get("pending_block_identity_descriptors")
    assert isinstance(descriptors, list)
    assert any(
        isinstance(item, dict)
        and str(item.get("block_id") or "") == bid
        and str(item.get("block_hash") or "") == bh
        and int(item.get("height") or 0) == 1
        for item in descriptors
    )
