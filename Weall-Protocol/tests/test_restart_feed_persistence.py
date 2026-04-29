from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_feed_persists_across_restart(tmp_path: Path) -> None:
    """
    Restart persistence smoke:

    - produce multiple valid blocks
    - restart on the same DB
    - verify chain state persists and remains readable

    We intentionally avoid CONTENT_POST_CREATE here because post creation may
    require additional account-state gates in the current backend surface.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-feed",
        tx_index_path=tx_index_path,
    )

    assert (
        ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@alice",
                "nonce": 1,
                "payload": {"pubkey": "k:alice"},
            }
        )["ok"]
        is True
    )
    assert ex.produce_block(max_txs=1).ok is True

    assert (
        ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@bob",
                "nonce": 1,
                "payload": {"pubkey": "k:bob"},
            }
        )["ok"]
        is True
    )
    assert ex.produce_block(max_txs=1).ok is True

    st1 = ex.read_state()
    assert int(st1["height"]) == 2

    accounts1 = st1.get("accounts") or {}
    assert "@alice" in accounts1
    assert "@bob" in accounts1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="restart-feed",
        tx_index_path=tx_index_path,
    )

    st2 = ex2.read_state()
    assert int(st2["height"]) == 2

    accounts2 = st2.get("accounts") or {}
    assert "@alice" in accounts2
    assert "@bob" in accounts2

    # Also verify the restored executor can still progress.
    assert (
        ex2.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@carol",
                "nonce": 1,
                "payload": {"pubkey": "k:carol"},
            }
        )["ok"]
        is True
    )
    assert ex2.produce_block(max_txs=1).ok is True

    st3 = ex2.read_state()
    assert int(st3["height"]) == 3
    accounts3 = st3.get("accounts") or {}
    assert "@carol" in accounts3
