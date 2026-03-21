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


def _account_key_count(state: dict, signer: str) -> int:
    acct = state.get("accounts", {}).get(signer, {})
    return len(acct.get("keys", {}).get("by_id", {}))


def test_duplicate_submit_same_nonce_is_not_double_committed_batch49(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "dup.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch49-dup",
        tx_index_path=tx_index_path,
    )

    r1 = _submit_account_register(ex, signer="@alice", nonce=1)
    r2 = _submit_account_register(ex, signer="@alice", nonce=1)

    assert r1.get("ok") is True
    assert r2.get("ok") in {True, False}

    while ex.read_mempool():
        meta = ex.produce_block(max_txs=10)
        assert meta.ok is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v1",
        chain_id="batch49-dup",
        tx_index_path=tx_index_path,
    )
    st = ex2.read_state()
    assert "@alice" in st.get("accounts", {})
    assert _account_key_count(st, "@alice") == 1
    assert int(ex2.read_state().get("height", 0)) >= 1


def test_out_of_order_nonces_do_not_create_multiple_effects_batch49(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "nonce_order.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch49-nonce-order",
        tx_index_path=tx_index_path,
    )

    r2 = _submit_account_register(ex, signer="@bob", nonce=2)
    r1 = _submit_account_register(ex, signer="@bob", nonce=1)

    assert r1.get("ok") is True
    assert r2.get("ok") in {True, False}

    for _ in range(5):
        mp_before = list(ex.read_mempool())
        if not mp_before:
            break
        meta = ex.produce_block(max_txs=10)
        assert meta.ok is True
        mp_after = list(ex.read_mempool())
        if mp_after == mp_before:
            break

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v2",
        chain_id="batch49-nonce-order",
        tx_index_path=tx_index_path,
    )
    st = ex2.read_state()
    assert "@bob" in st.get("accounts", {})
    assert _account_key_count(st, "@bob") == 1


def test_replay_after_restart_does_not_reintroduce_confirmed_effect_batch49(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "replay.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch49-replay",
        tx_index_path=tx_index_path,
    )

    r1 = _submit_account_register(ex, signer="@carol", nonce=1)
    assert r1.get("ok") is True

    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch49-replay",
        tx_index_path=tx_index_path,
    )
    st2 = ex2.read_state()
    assert "@carol" in st2.get("accounts", {})
    assert _account_key_count(st2, "@carol") == 1

    replay = _submit_account_register(ex2, signer="@carol", nonce=1)
    assert replay.get("ok") in {True, False}

    for _ in range(3):
        if not ex2.read_mempool():
            break
        meta2 = ex2.produce_block(max_txs=10)
        assert meta2.ok is True

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v3",
        chain_id="batch49-replay",
        tx_index_path=tx_index_path,
    )
    st3 = ex3.read_state()
    assert "@carol" in st3.get("accounts", {})
    assert _account_key_count(st3, "@carol") == 1


def test_partial_sequence_restart_preserves_single_canonical_result_batch49(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "partial.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch49-partial",
        tx_index_path=tx_index_path,
    )

    assert _submit_account_register(ex, signer="@dave", nonce=1).get("ok") is True
    assert _submit_account_register(ex, signer="@erin", nonce=1).get("ok") is True

    meta1 = ex.produce_block(max_txs=1)
    assert meta1.ok is True
    first_tip = str(ex.get_latest_block().get("block_id") or "")
    assert first_tip

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch49-partial",
        tx_index_path=tx_index_path,
    )
    assert int(ex2.read_state().get("height", 0)) == 1

    if ex2.read_mempool():
        meta2 = ex2.produce_block(max_txs=10)
        assert meta2.ok is True

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="v4",
        chain_id="batch49-partial",
        tx_index_path=tx_index_path,
    )
    st3 = ex3.read_state()
    assert "@dave" in st3.get("accounts", {})
    assert "@erin" in st3.get("accounts", {})
    assert _account_key_count(st3, "@dave") == 1
    assert _account_key_count(st3, "@erin") == 1
    assert int(st3.get("height", 0)) >= 1
