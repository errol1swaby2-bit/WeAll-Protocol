from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.helper_planner import canonicalize_txs
from weall.runtime.mempool import PersistentMempool
from weall.runtime.sqlite_db import SqliteDB


def test_domain_dispatch_rejects_noncanonical_unknown_tx_type_batch116() -> None:
    state = {"accounts": {}, "params": {}, "meta": {}, "height": 0}
    with pytest.raises(ApplyError, match="noncanonical_legacy_tx_type"):
        apply_tx(
            state,
            {
                "tx_type": "ACCOUNT_RECOVERY_PROPOSE",
                "signer": "@alice",
                "nonce": 1,
                "payload": {},
            },
        )


def test_helper_planner_order_no_longer_depends_on_received_ms_batch116() -> None:
    txs = [
        {"tx_id": "tx-b", "received_ms": 1_000, "signer": "@b", "nonce": 1},
        {"tx_id": "tx-a", "received_ms": 1, "signer": "@a", "nonce": 1},
    ]
    ordered = canonicalize_txs(list(reversed(txs)))
    assert [str(tx.get("tx_id") or "") for tx in ordered] == ["tx-a", "tx-b"]


def test_mempool_canonical_fetch_uses_canonical_sql_order_before_limit_batch116(tmp_path: Path) -> None:
    db = SqliteDB(path=str(tmp_path / "mempool.db"))
    pool = PersistentMempool(db=db, chain_id="weall-test")

    for signer in ["@carol", "@alice", "@bob"]:
        meta = pool.add(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": signer,
                "nonce": 1,
                "payload": {"pubkey": f"k:{signer}"},
            }
        )
        assert meta["ok"] is True

    selected = pool.fetch_for_block(limit=2, policy="canonical")
    assert [str(tx.get("signer") or "") for tx in selected] == ["@alice", "@bob"]
