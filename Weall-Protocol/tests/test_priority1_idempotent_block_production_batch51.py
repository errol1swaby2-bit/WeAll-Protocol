from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _submit(ex: WeAllExecutor, signer: str, nonce: int) -> None:
    res = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}:{nonce}"},
        }
    )
    assert res.get("ok") is True


def test_mempool_rehydration_matches_pre_restart_state_batch51(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "rehydrate.db")
    ex = WeAllExecutor(db_path=db_path, node_id="v1", chain_id="b51", tx_index_path=tx_index_path)

    _submit(ex, "@a", 1)
    _submit(ex, "@b", 1)

    before = list(ex.read_mempool())
    assert len(before) == 2

    ex2 = WeAllExecutor(db_path=db_path, node_id="v1", chain_id="b51", tx_index_path=tx_index_path)
    after = list(ex2.read_mempool())

    assert len(after) == len(before)


def test_block_production_is_idempotent_under_repeated_calls_batch51(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "idem.db")
    ex = WeAllExecutor(db_path=db_path, node_id="v2", chain_id="b51", tx_index_path=tx_index_path)

    _submit(ex, "@c", 1)

    meta1 = ex.produce_block(max_txs=10)
    assert meta1.ok is True

    height_after_first = int(ex.read_state().get("height", 0))

    # calling again with empty mempool should not advance state incorrectly
    meta2 = ex.produce_block(max_txs=10)
    assert meta2.ok is True

    height_after_second = int(ex.read_state().get("height", 0))

    assert height_after_second == height_after_first


def test_repeated_restart_produce_cycle_does_not_duplicate_effects_batch51(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "cycle.db")

    ex = WeAllExecutor(db_path=db_path, node_id="v3", chain_id="b51", tx_index_path=tx_index_path)

    _submit(ex, "@d", 1)

    for _ in range(3):
        if ex.read_mempool():
            meta = ex.produce_block(max_txs=10)
            assert meta.ok is True

        ex = WeAllExecutor(
            db_path=db_path, node_id="v3", chain_id="b51", tx_index_path=tx_index_path
        )

    st = ex.read_state()
    acct = st.get("accounts", {}).get("@d", {})
    keys = acct.get("keys", {}).get("by_id", {})
    assert len(keys) == 1


def test_height_monotonicity_across_restart_and_empty_blocks_batch51(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "height.db")

    ex = WeAllExecutor(db_path=db_path, node_id="v4", chain_id="b51", tx_index_path=tx_index_path)

    _submit(ex, "@e", 1)

    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    h1 = int(ex.read_state().get("height", 0))

    ex2 = WeAllExecutor(db_path=db_path, node_id="v4", chain_id="b51", tx_index_path=tx_index_path)

    meta2 = ex2.produce_block(max_txs=10)
    assert meta2.ok is True

    h2 = int(ex2.read_state().get("height", 0))

    assert h2 >= h1
