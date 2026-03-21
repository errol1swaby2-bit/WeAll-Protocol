from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _submit(ex: WeAllExecutor, signer: str, nonce: int) -> dict:
    return ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}:{nonce}"},
        }
    )


def _latest_block_id(ex: WeAllExecutor) -> str:
    latest = ex.get_latest_block()
    if not isinstance(latest, dict):
        return ""
    return str(latest.get("block_id") or "")


def test_committed_tip_is_stable_across_multiple_executor_reopens_batch68(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "tip.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="n1",
        chain_id="batch68-tip",
        tx_index_path=tx_index_path,
    )
    assert _submit(ex, "@a", 1).get("ok") is True
    assert ex.produce_block(max_txs=10).ok is True

    expected_height = int(ex.read_state().get("height", 0))
    expected_tip = _latest_block_id(ex)
    expected_accounts = dict(ex.read_state().get("accounts", {}))

    for _ in range(5):
        ex = WeAllExecutor(
            db_path=db_path,
            node_id="n1",
            chain_id="batch68-tip",
            tx_index_path=tx_index_path,
        )
        assert int(ex.read_state().get("height", 0)) == expected_height
        assert _latest_block_id(ex) == expected_tip
        assert dict(ex.read_state().get("accounts", {})) == expected_accounts
        assert len(ex.read_mempool()) == 0


def test_partial_commit_then_restart_then_resume_preserves_canonical_result_batch68(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "partial.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="n2",
        chain_id="batch68-partial",
        tx_index_path=tx_index_path,
    )
    for signer in ["@b", "@c", "@d"]:
        assert _submit(ex, signer, 1).get("ok") is True

    assert ex.produce_block(max_txs=1).ok is True
    partial_height = int(ex.read_state().get("height", 0))
    assert partial_height >= 1

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="n2",
        chain_id="batch68-partial",
        tx_index_path=tx_index_path,
    )
    pending = list(ex.read_mempool())
    assert len(pending) >= 1

    while ex.read_mempool():
        assert ex.produce_block(max_txs=10).ok is True

    st = ex.read_state()
    for signer in ["@b", "@c", "@d"]:
        assert signer in st.get("accounts", {})
    assert len(ex.read_mempool()) == 0
    assert int(st.get("height", 0)) >= partial_height


def test_empty_production_after_commit_does_not_reopen_mempool_batch68(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "empty_after_commit.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="n3",
        chain_id="batch68-empty-after-commit",
        tx_index_path=tx_index_path,
    )
    assert _submit(ex, "@e", 1).get("ok") is True
    assert ex.produce_block(max_txs=10).ok is True

    expected_height = int(ex.read_state().get("height", 0))
    expected_tip = _latest_block_id(ex)

    for _ in range(3):
        assert ex.produce_block(max_txs=10).ok is True
        assert len(ex.read_mempool()) == 0
        assert int(ex.read_state().get("height", 0)) == expected_height
        assert _latest_block_id(ex) == expected_tip

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="n3",
        chain_id="batch68-empty-after-commit",
        tx_index_path=tx_index_path,
    )
    assert len(ex.read_mempool()) == 0
    assert int(ex.read_state().get("height", 0)) == expected_height
    assert _latest_block_id(ex) == expected_tip


def test_same_logical_work_with_many_restarts_matches_single_run_batch68(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    signers = ["@f", "@g", "@h", "@i"]

    db_a = str(tmp_path / "single.db")
    ex_a = WeAllExecutor(
        db_path=db_a,
        node_id="n4",
        chain_id="batch68-single",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        assert _submit(ex_a, signer, 1).get("ok") is True
    while ex_a.read_mempool():
        assert ex_a.produce_block(max_txs=10).ok is True
    accounts_a = dict(ex_a.read_state().get("accounts", {}))

    db_b = str(tmp_path / "restarty.db")
    ex_b = WeAllExecutor(
        db_path=db_b,
        node_id="n4",
        chain_id="batch68-restarty",
        tx_index_path=tx_index_path,
    )
    for signer in signers:
        assert _submit(ex_b, signer, 1).get("ok") is True

    while ex_b.read_mempool():
        assert ex_b.produce_block(max_txs=1).ok is True
        ex_b = WeAllExecutor(
            db_path=db_b,
            node_id="n4",
            chain_id="batch68-restarty",
            tx_index_path=tx_index_path,
        )

    accounts_b = dict(ex_b.read_state().get("accounts", {}))
    assert accounts_a == accounts_b
