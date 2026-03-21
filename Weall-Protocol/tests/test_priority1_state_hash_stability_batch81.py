from __future__ import annotations

import hashlib
import json
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


def _normalized_logical_state(ex: WeAllExecutor) -> dict:
    st = ex.read_state()
    return {
        "accounts": st.get("accounts", {}),
        # Height is intentionally excluded because different batching strategies
        # can legally produce different numbers of blocks while preserving the
        # same logical committed state.
        "nonces": st.get("nonces", {}),
    }


def _state_hash(ex: WeAllExecutor) -> str:
    payload = json.dumps(
        _normalized_logical_state(ex),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_restart_preserves_normalized_state_hash_batch81() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db = str(root / ".pytest-b81-a.db")
    try:
        Path(db).unlink(missing_ok=True)

        ex = WeAllExecutor(db_path=db, node_id="n1", chain_id="b81", tx_index_path=tx_index_path)
        for signer in ["@a", "@b"]:
            assert _submit(ex, signer, 1).get("ok") is True
        while ex.read_mempool():
            assert ex.produce_block(max_txs=10).ok is True

        h1 = _state_hash(ex)

        ex2 = WeAllExecutor(db_path=db, node_id="n1", chain_id="b81", tx_index_path=tx_index_path)
        h2 = _state_hash(ex2)

        assert h1 == h2
    finally:
        Path(db).unlink(missing_ok=True)


def test_chunking_preserves_normalized_state_hash_batch81() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db1 = str(root / ".pytest-b81-b1.db")
    db2 = str(root / ".pytest-b81-b2.db")
    try:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)

        ex1 = WeAllExecutor(db_path=db1, node_id="n1", chain_id="b81c", tx_index_path=tx_index_path)
        ex2 = WeAllExecutor(db_path=db2, node_id="n1", chain_id="b81c", tx_index_path=tx_index_path)

        for signer in ["@c", "@d", "@e"]:
            assert _submit(ex1, signer, 1).get("ok") is True
            assert _submit(ex2, signer, 1).get("ok") is True

        while ex1.read_mempool():
            assert ex1.produce_block(max_txs=1).ok is True
        while ex2.read_mempool():
            assert ex2.produce_block(max_txs=10).ok is True

        assert _state_hash(ex1) == _state_hash(ex2)
    finally:
        Path(db1).unlink(missing_ok=True)
        Path(db2).unlink(missing_ok=True)


def test_rejected_replay_does_not_change_state_hash_batch81() -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db = str(root / ".pytest-b81-c.db")
    try:
        Path(db).unlink(missing_ok=True)

        ex = WeAllExecutor(db_path=db, node_id="n1", chain_id="b81r", tx_index_path=tx_index_path)
        assert _submit(ex, "@x", 1).get("ok") is True
        while ex.read_mempool():
            assert ex.produce_block(max_txs=10).ok is True

        h1 = _state_hash(ex)

        res = _submit(ex, "@x", 1)
        assert res.get("ok") is False

        h2 = _state_hash(ex)
        assert h1 == h2
    finally:
        Path(db).unlink(missing_ok=True)
