from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_block_candidate_selection_is_deterministic(tmp_path: Path) -> None:
    """
    Two fresh executors fed the same tx sequence should build the same next
    block candidate selection result.

    We assert determinism on the selected tx ids and resulting next-state height,
    not on executor-internal block dict layout.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")

    ex_a = WeAllExecutor(
        db_path=db_a,
        node_id="@alice",
        chain_id="deterministic-candidate",
        tx_index_path=tx_index_path,
    )
    ex_b = WeAllExecutor(
        db_path=db_b,
        node_id="@bob",
        chain_id="deterministic-candidate",
        tx_index_path=tx_index_path,
    )

    txs = [
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user1",
            "nonce": 1,
            "payload": {"pubkey": "k:user1"},
        },
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user2",
            "nonce": 1,
            "payload": {"pubkey": "k:user2"},
        },
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user3",
            "nonce": 1,
            "payload": {"pubkey": "k:user3"},
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
    assert len(applied_a) == 2
    assert int(st_a["height"]) == int(st_b["height"])

    # Also verify the candidate block identities line up on deterministic fields
    # that are expected to exist in the current executor shape.
    assert int(blk_a["height"]) == int(blk_b["height"])
    assert str(blk_a["prev_block_id"]) == str(blk_b["prev_block_id"])
