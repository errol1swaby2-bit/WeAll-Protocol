from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_tx_replay_rejected_after_confirmed_restart(tmp_path: Path) -> None:
    """
    Once a tx is confirmed, replaying the exact same tx after restart must not
    re-enter the mempool or be re-applied.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@replay",
        "nonce": 1,
        "payload": {"pubkey": "k:replay"},
    }

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="replay-after-confirm",
        tx_index_path=tx_index_path,
    )

    sub1 = ex1.submit_tx(dict(tx))
    assert sub1["ok"] is True

    meta1 = ex1.produce_block(max_txs=1)
    assert meta1.ok is True
    assert int(meta1.applied_count) == 1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="replay-after-confirm",
        tx_index_path=tx_index_path,
    )

    sub2 = ex2.submit_tx(dict(tx))

    # It may be rejected immediately, or otherwise prevented from reappearing
    # in the live pending set. In either case it must not become pending.
    if sub2.get("ok") is True:
        mp = ex2.read_mempool()
        tx_ids = [t["tx_id"] for t in mp]
        assert sub1["tx_id"] not in tx_ids
    else:
        assert sub2["ok"] is False
