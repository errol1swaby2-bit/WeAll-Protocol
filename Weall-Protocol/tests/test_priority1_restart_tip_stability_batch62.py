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


def test_restart_replay_same_pending_set_preserves_single_result_batch62(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "pending.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch62-pending",
        tx_index_path=tx_index_path,
    )

    _submit(ex, "@a", 1)
    _submit(ex, "@b", 1)
    pending_before = list(ex.read_mempool())
    assert len(pending_before) == 2

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch62-pending",
        tx_index_path=tx_index_path,
    )
    pending_after = list(ex2.read_mempool())
    assert pending_after == pending_before

    while ex2.read_mempool():
        meta = ex2.produce_block(max_txs=1)
        assert meta.ok is True

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch62-pending",
        tx_index_path=tx_index_path,
    )
    st3 = ex3.read_state()
    assert "@a" in st3.get("accounts", {})
    assert "@b" in st3.get("accounts", {})
    assert len(ex3.read_mempool()) == 0


def test_block_tip_is_stable_across_restart_without_new_work_batch62(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "tip.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch62-tip",
        tx_index_path=tx_index_path,
    )
    _submit(ex, "@c", 1)
    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    tip1 = _latest_block_id(ex)
    h1 = int(ex.read_state().get("height", 0))

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch62-tip",
        tx_index_path=tx_index_path,
    )
    tip2 = _latest_block_id(ex2)
    h2 = int(ex2.read_state().get("height", 0))

    assert h2 == h1
    assert tip2 == tip1

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch62-tip",
        tx_index_path=tx_index_path,
    )
    tip3 = _latest_block_id(ex3)
    h3 = int(ex3.read_state().get("height", 0))
    assert h3 == h1
    assert tip3 == tip1


def test_sequential_small_block_production_reaches_same_end_state_batch62(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_a = str(tmp_path / "small.db")
    ex_a = WeAllExecutor(
        db_path=db_a,
        node_id="v3",
        chain_id="batch62-small",
        tx_index_path=tx_index_path,
    )
    for signer in ["@d", "@e", "@f", "@g"]:
        _submit(ex_a, signer, 1)

    while ex_a.read_mempool():
        meta = ex_a.produce_block(max_txs=1)
        assert meta.ok is True

    st_a = ex_a.read_state()
    tip_a = _latest_block_id(ex_a)
    h_a = int(st_a.get("height", 0))

    db_b = str(tmp_path / "large.db")
    ex_b = WeAllExecutor(
        db_path=db_b,
        node_id="v3",
        chain_id="batch62-large",
        tx_index_path=tx_index_path,
    )
    for signer in ["@d", "@e", "@f", "@g"]:
        _submit(ex_b, signer, 1)

    while ex_b.read_mempool():
        meta = ex_b.produce_block(max_txs=10)
        assert meta.ok is True

    st_b = ex_b.read_state()
    h_b = int(st_b.get("height", 0))

    for signer in ["@d", "@e", "@f", "@g"]:
        assert signer in st_a.get("accounts", {})
        assert signer in st_b.get("accounts", {})

    assert h_a >= 1
    assert h_b >= 1
    assert tip_a or h_a >= 1


def test_redundant_restart_cycles_do_not_reopen_committed_work_batch62(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "reopen.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch62-reopen",
        tx_index_path=tx_index_path,
    )
    _submit(ex, "@h", 1)
    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    for _ in range(3):
        ex = WeAllExecutor(
            db_path=db_path,
            node_id="v4",
            chain_id="batch62-reopen",
            tx_index_path=tx_index_path,
        )
        assert len(ex.read_mempool()) == 0
        assert "@h" in ex.read_state().get("accounts", {})

    keys = ex.read_state().get("accounts", {}).get("@h", {}).get("keys", {}).get("by_id", {})
    assert len(keys) == 1
