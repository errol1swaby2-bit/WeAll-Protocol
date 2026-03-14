from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_nonce_increments_across_blocks(tmp_path: Path) -> None:
    """
    A user submitting sequential txs across multiple blocks
    must have nonce enforced strictly.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="nonce-cross-block",
        tx_index_path=tx_index_path,
    )

    r1 = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user",
            "nonce": 1,
            "payload": {"pubkey": "k:user"},
        }
    )

    assert r1["ok"] is True

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True

    r2 = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user",
            "nonce": 2,
            "payload": {"pubkey": "k:user2"},
        }
    )

    assert r2["ok"] is True
