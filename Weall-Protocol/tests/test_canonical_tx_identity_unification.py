from __future__ import annotations

from weall.runtime.mempool import compute_tx_id as mempool_compute_tx_id
from weall.runtime.tx_id import compute_tx_id_from_dict


def _tx(*, sig: str) -> dict:
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": "k:@alice"},
        "sig": sig,
        "sig_profile": "pq-mldsa-v1",
        "signature": {"sig": sig, "profile": "pq-mldsa-v1"},
        "network_id": "local-transport-only",
    }


def test_mempool_and_runtime_use_one_signature_independent_transaction_id() -> None:
    chain_id = "tx-id-unification"
    left = _tx(sig="aa")
    right = _tx(sig="bb")

    left_runtime = compute_tx_id_from_dict(chain_id, left)
    right_runtime = compute_tx_id_from_dict(chain_id, right)
    left_mempool = mempool_compute_tx_id(left, chain_id=chain_id)
    right_mempool = mempool_compute_tx_id(right, chain_id=chain_id)

    assert left_runtime.startswith("tx:")
    assert left_runtime == right_runtime
    assert left_mempool == right_mempool == left_runtime


def test_persisted_legacy_mempool_id_migrates_transactionally(tmp_path) -> None:
    import hashlib
    import json

    from weall.runtime.mempool import PersistentMempool
    from weall.runtime.sqlite_db import SqliteDB

    chain_id = "tx-id-migration"
    env = _tx(sig="legacy-signature")
    legacy_base = dict(env)
    legacy_base["chain_id"] = chain_id
    legacy_json = json.dumps(legacy_base, sort_keys=True, separators=(",", ":"))
    legacy_id = "tx:" + hashlib.sha256(legacy_json.encode("utf-8")).hexdigest()
    canonical_id = compute_tx_id_from_dict(chain_id, env)
    assert legacy_id != canonical_id

    db = SqliteDB(path=str(tmp_path / "mempool.sqlite"))
    db.init_schema()
    stored = dict(env)
    stored["tx_id"] = legacy_id
    with db.write_tx() as con:
        con.execute(
            """
            INSERT INTO mempool(
                tx_id, envelope_json, signer, tx_type, nonce,
                received_ms, expires_ms, admitted_at_height, expires_at_height
            ) VALUES(?,?,?,?,?,?,?,?,?);
            """,
            (
                legacy_id,
                json.dumps(stored, sort_keys=True, separators=(",", ":")),
                "@alice",
                "ACCOUNT_REGISTER",
                1,
                1,
                9999999999999,
                0,
                0,
            ),
        )

    pool = PersistentMempool(db=db, chain_id=chain_id)
    assert pool.contains(legacy_id) is False
    assert pool.contains(canonical_id) is True
    rows = pool.peek(limit=10)
    assert len(rows) == 1
    assert rows[0]["tx_id"] == canonical_id
