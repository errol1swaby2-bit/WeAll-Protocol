from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_duplicate_tx_rejected_or_deduped(tmp_path: Path) -> None:
    """
    Submitting the exact same tx twice must not result in two
    mempool entries.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="dup-tx-test",
        tx_index_path=tx_index_path,
    )

    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@dupuser",
        "nonce": 1,
        "payload": {"pubkey": "k:dup"},
    }

    r1 = ex.submit_tx(dict(tx))
    ex.submit_tx(dict(tx))

    assert r1["ok"] is True

    mp = ex.read_mempool()
    tx_ids = [t["tx_id"] for t in mp]

    # either rejected or deduped — but must appear only once
    assert tx_ids.count(r1["tx_id"]) == 1
