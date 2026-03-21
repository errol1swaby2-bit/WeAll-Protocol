from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _submit_account_register(ex: WeAllExecutor, *, signer: str, nonce: int) -> dict:
    return ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}:{nonce}"},
        }
    )


def _account_exists(state: dict, signer: str) -> bool:
    return signer in state.get("accounts", {})


def test_mempool_restart_then_commit_preserves_single_effect_batch50(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "mempool_restart.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch50-mempool-restart",
        tx_index_path=tx_index_path,
    )

    assert _submit_account_register(ex, signer="@alice", nonce=1).get("ok") is True
    assert _submit_account_register(ex, signer="@bob", nonce=1).get("ok") is True
    assert len(ex.read_mempool()) == 2

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch50-mempool-restart",
        tx_index_path=tx_index_path,
    )
    assert len(ex2.read_mempool()) == 2

    while ex2.read_mempool():
        meta = ex2.produce_block(max_txs=10)
        assert meta.ok is True

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch50-mempool-restart",
        tx_index_path=tx_index_path,
    )
    st3 = ex3.read_state()
    assert _account_exists(st3, "@alice")
    assert _account_exists(st3, "@bob")
    assert len(ex3.read_mempool()) == 0


def test_invalid_then_valid_sequence_does_not_poison_following_progress_batch50(
    tmp_path: Path,
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "invalid_valid.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch50-invalid-valid",
        tx_index_path=tx_index_path,
    )

    bad = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@carol",
            "nonce": 0,
            "payload": {"pubkey": "k:@carol:0"},
        }
    )
    good = _submit_account_register(ex, signer="@carol", nonce=1)

    assert bad.get("ok") in {True, False}
    assert good.get("ok") is True

    for _ in range(3):
        if not ex.read_mempool():
            break
        meta = ex.produce_block(max_txs=10)
        assert meta.ok is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch50-invalid-valid",
        tx_index_path=tx_index_path,
    )
    st2 = ex2.read_state()
    assert _account_exists(st2, "@carol")


def test_duplicate_submission_after_restart_does_not_create_duplicate_effect_batch50(
    tmp_path: Path,
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "dup_restart.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch50-dup-restart",
        tx_index_path=tx_index_path,
    )

    assert _submit_account_register(ex, signer="@dave", nonce=1).get("ok") is True
    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch50-dup-restart",
        tx_index_path=tx_index_path,
    )
    st2 = ex2.read_state()
    assert _account_exists(st2, "@dave")

    again = _submit_account_register(ex2, signer="@dave", nonce=1)
    assert again.get("ok") in {True, False}

    for _ in range(3):
        if not ex2.read_mempool():
            break
        meta2 = ex2.produce_block(max_txs=10)
        assert meta2.ok is True

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch50-dup-restart",
        tx_index_path=tx_index_path,
    )
    st3 = ex3.read_state()
    assert _account_exists(st3, "@dave")
    keys = st3.get("accounts", {}).get("@dave", {}).get("keys", {}).get("by_id", {})
    assert len(keys) == 1


def test_sequential_partial_commits_and_restarts_converge_batch50(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "partial_restart.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch50-partial-restart",
        tx_index_path=tx_index_path,
    )

    assert _submit_account_register(ex, signer="@erin", nonce=1).get("ok") is True
    assert _submit_account_register(ex, signer="@frank", nonce=1).get("ok") is True
    assert _submit_account_register(ex, signer="@grace", nonce=1).get("ok") is True

    meta1 = ex.produce_block(max_txs=1)
    assert meta1.ok is True
    assert int(ex.read_state().get("height", 0)) == 1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch50-partial-restart",
        tx_index_path=tx_index_path,
    )
    assert int(ex2.read_state().get("height", 0)) == 1
    assert len(ex2.read_mempool()) >= 1

    meta2 = ex2.produce_block(max_txs=1)
    assert meta2.ok is True

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch50-partial-restart",
        tx_index_path=tx_index_path,
    )
    if ex3.read_mempool():
        meta3 = ex3.produce_block(max_txs=10)
        assert meta3.ok is True

    ex4 = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch50-partial-restart",
        tx_index_path=tx_index_path,
    )
    st4 = ex4.read_state()
    assert _account_exists(st4, "@erin")
    assert _account_exists(st4, "@frank")
    assert _account_exists(st4, "@grace")
    assert len(ex4.read_mempool()) == 0
    assert int(st4.get("height", 0)) >= 2
