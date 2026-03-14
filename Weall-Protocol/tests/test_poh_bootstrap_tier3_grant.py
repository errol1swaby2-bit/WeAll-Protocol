from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair, sign_tx_dict


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_poh_related_state_can_be_persisted_in_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SQLite migration invariant:

    The ledger snapshot is stored in SQLite. It must be able to persist PoH-relevant
    state structures without requiring JSON-file shims or admin-only routes.

    Production parity:
      - txs must be signed to enter mempool after account exists
      - include a seed pubkey at register so later txs can be verified
    """
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="poh-snapshot", tx_index_path=tx_index_path)

    alice_pubkey, _ = deterministic_ed25519_keypair(label="@alice")

    # Create user account with seed pubkey.
    reg = {"tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "payload": {"pubkey": alice_pubkey}}
    assert ex.submit_tx(sign_tx_dict(reg, label="@alice"))["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    # Submit PoH-related txs (exact types depend on canon; this test is primarily persistence).
    # We use a no-op produce to ensure snapshot write path works with existing state fields.
    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True

    # Snapshot must still be readable and contain PoH dict (even if empty).
    st = ex.read_state()
    assert "poh" in st
