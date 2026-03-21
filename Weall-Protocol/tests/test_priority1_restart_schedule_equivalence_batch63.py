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


def _latest_block_id(ex: WeAllExecutor) -> str:
    latest = ex.get_latest_block()
    if not isinstance(latest, dict):
        return ""
    return str(latest.get("block_id") or "")


def test_restart_schedule_variation_reaches_same_accounts_batch63(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    signers = ["@a", "@b", "@c", "@d", "@e"]

    db_a = str(tmp_path / "sched_a.db")
    ex_a = WeAllExecutor(
        db_path=db_a,
        node_id="v1",
        chain_id="batch63-a",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        _submit(ex_a, signer, 1)

    while ex_a.read_mempool():
        meta = ex_a.produce_block(max_txs=10)
        assert meta.ok is True

    st_a = ex_a.read_state()

    db_b = str(tmp_path / "sched_b.db")
    ex_b = WeAllExecutor(
        db_path=db_b,
        node_id="v1",
        chain_id="batch63-b",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        _submit(ex_b, signer, 1)

    while ex_b.read_mempool():
        meta = ex_b.produce_block(max_txs=2)
        assert meta.ok is True
        ex_b = WeAllExecutor(
            db_path=db_b,
            node_id="v1",
            chain_id="batch63-b",
            tx_index_path=tx_index_path,
        )

    st_b = ex_b.read_state()

    for signer in signers:
        assert signer in st_a.get("accounts", {})
        assert signer in st_b.get("accounts", {})

    assert len(st_a.get("accounts", {})) == len(st_b.get("accounts", {}))


def test_tip_stability_across_many_restarts_without_new_work_batch63(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "tip.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch63-tip",
        tx_index_path=tx_index_path,
    )
    _submit(ex, "@z", 1)
    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    expected_tip = _latest_block_id(ex)
    expected_height = int(ex.read_state().get("height", 0))

    for _ in range(5):
        ex = WeAllExecutor(
            db_path=db_path,
            node_id="v2",
            chain_id="batch63-tip",
            tx_index_path=tx_index_path,
        )
        assert _latest_block_id(ex) == expected_tip
        assert int(ex.read_state().get("height", 0)) == expected_height
        assert len(ex.read_mempool()) == 0


def test_redundant_empty_production_after_restart_does_not_mutate_state_batch63(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "empty.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch63-empty",
        tx_index_path=tx_index_path,
    )
    _submit(ex, "@m", 1)
    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    expected_tip = _latest_block_id(ex)
    expected_height = int(ex.read_state().get("height", 0))
    expected_accounts = sorted(ex.read_state().get("accounts", {}).keys())

    for _ in range(3):
        ex = WeAllExecutor(
            db_path=db_path,
            node_id="v3",
            chain_id="batch63-empty",
            tx_index_path=tx_index_path,
        )
        meta2 = ex.produce_block(max_txs=10)
        assert meta2.ok is True
        assert _latest_block_id(ex) == expected_tip
        assert int(ex.read_state().get("height", 0)) == expected_height
        assert sorted(ex.read_state().get("accounts", {}).keys()) == expected_accounts


def test_pending_then_committed_then_restart_never_reopens_keys_batch63(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "keys.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch63-keys",
        tx_index_path=tx_index_path,
    )
    _submit(ex, "@k", 1)
    assert len(ex.read_mempool()) == 1

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch63-keys",
        tx_index_path=tx_index_path,
    )
    assert len(ex.read_mempool()) == 1

    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    for _ in range(4):
        ex = WeAllExecutor(
            db_path=db_path,
            node_id="v4",
            chain_id="batch63-keys",
            tx_index_path=tx_index_path,
        )
        assert len(ex.read_mempool()) == 0
        keys = ex.read_state().get("accounts", {}).get("@k", {}).get("keys", {}).get("by_id", {})
        assert len(keys) == 1
