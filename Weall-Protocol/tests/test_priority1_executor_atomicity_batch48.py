from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_executor_state_persistence_is_atomic_across_restarts_batch48(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "atomic.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch48-atomic",
        tx_index_path=tx_index_path,
    )

    st = ex.read_state()
    st["accounts"]["alice"] = {"balance": 100}
    ex.state = st
    ex._ledger_store.write(ex.state)

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch48-atomic",
        tx_index_path=tx_index_path,
    )
    st2 = ex2.read_state()

    assert "alice" in st2.get("accounts", {})
    assert st2["accounts"]["alice"]["balance"] == 100


def test_executor_state_does_not_partially_persist_on_multiple_writes_batch48(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "multiwrite.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch48-multi",
        tx_index_path=tx_index_path,
    )

    for i in range(5):
        st = ex.read_state()
        st["accounts"][f"user{i}"] = {"balance": i * 10}
        ex.state = st
        ex._ledger_store.write(ex.state)

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch48-multi",
        tx_index_path=tx_index_path,
    )
    st2 = ex2.read_state()

    for i in range(5):
        assert st2["accounts"][f"user{i}"]["balance"] == i * 10


def test_executor_restart_does_not_reset_bft_or_consensus_state_batch48(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "bft.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch48-bft",
        tx_index_path=tx_index_path,
    )

    ex.bft_set_view(5)

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch48-bft",
        tx_index_path=tx_index_path,
    )

    assert int(ex2.state.get("bft", {}).get("view") or 0) == 5


def test_executor_state_integrity_under_sequential_restarts_batch48(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_path = str(tmp_path / "restart.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch48-restart",
        tx_index_path=tx_index_path,
    )

    st = ex.read_state()
    st["meta"] = {"height": 10}
    ex.state = st
    ex._ledger_store.write(ex.state)

    for _ in range(3):
        ex = WeAllExecutor(
            db_path=db_path,
            node_id="v4",
            chain_id="batch48-restart",
            tx_index_path=tx_index_path,
        )
        st = ex.read_state()
        assert st.get("meta", {}).get("height") == 10
