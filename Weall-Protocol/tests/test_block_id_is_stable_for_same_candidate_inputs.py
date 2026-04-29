from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_block_candidate_core_fields_are_stable_for_same_inputs(tmp_path: Path) -> None:
    """
    Two independent executors with identical pre-state and identical pending txs
    should build equivalent candidate blocks on deterministic fields.

    Note:
      Current block_id shape includes a time-derived component, so we do NOT
      assert equality of block_id across independently built candidates.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")

    ex_a = WeAllExecutor(
        db_path=db_a,
        node_id="@a",
        chain_id="stable-block-id",
        tx_index_path=tx_index_path,
    )
    ex_b = WeAllExecutor(
        db_path=db_b,
        node_id="@b",
        chain_id="stable-block-id",
        tx_index_path=tx_index_path,
    )

    txs = [
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@u1",
            "nonce": 1,
            "payload": {"pubkey": "k:u1"},
        },
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@u2",
            "nonce": 1,
            "payload": {"pubkey": "k:u2"},
        },
    ]

    for tx in txs:
        assert ex_a.submit_tx(dict(tx))["ok"] is True
        assert ex_b.submit_tx(dict(tx))["ok"] is True

    blk_a, st_a, applied_a, invalid_a, err_a = ex_a.build_block_candidate(
        max_txs=2,
        allow_empty=False,
    )
    blk_b, st_b, applied_b, invalid_b, err_b = ex_b.build_block_candidate(
        max_txs=2,
        allow_empty=False,
    )

    assert err_a == ""
    assert err_b == ""
    assert applied_a == applied_b
    assert invalid_a == invalid_b

    assert int(blk_a["height"]) == int(blk_b["height"])
    assert str(blk_a["prev_block_id"]) == str(blk_b["prev_block_id"])
    assert int(st_a["height"]) == int(st_b["height"])

    # Sanity: each candidate should still produce a block id, just not a
    # cross-node deterministic one under the current implementation.
    assert str(blk_a["block_id"])
    assert str(blk_b["block_id"])
