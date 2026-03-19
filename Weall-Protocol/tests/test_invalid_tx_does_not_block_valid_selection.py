from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_invalid_tx_does_not_block_valid_selection(tmp_path: Path) -> None:
    """
    If the mempool contains an invalid tx, valid txs must still
    be selected for the block.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="invalid-skip",
        tx_index_path=tx_index_path,
    )

    ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user",
            "nonce": 5,  # invalid nonce
            "payload": {"pubkey": "k:bad"},
        }
    )

    good = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user2",
            "nonce": 1,
            "payload": {"pubkey": "k:good"},
        }
    )

    assert good["ok"] is True

    meta = ex.produce_block(max_txs=1)

    assert meta.ok is True
    assert int(meta.applied_count) == 1
