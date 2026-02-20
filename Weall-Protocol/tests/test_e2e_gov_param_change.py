from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair, sign_tx_dict


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_state_persists_across_blocks_and_restart(tmp_path: Path, monkeypatch) -> None:
    """Old gov-param-change test depended on legacy governance machinery.

    For SQLite migration, we keep the important invariant:
      - state mutations persist across blocks
      - restart reads the same state snapshot

    Production parity:
      - mempool admission should require valid signatures for user txs
      - account must first register a seed pubkey, then sign subsequent txs
    """
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="persist", tx_index_path=tx_index_path)

    alice_pubkey, _ = deterministic_ed25519_keypair(label="alice")

    # Create account with a seed pubkey so later txs can be signature-verified.
    reg = {"tx_type": "ACCOUNT_REGISTER", "signer": "alice", "nonce": 1, "payload": {"pubkey": alice_pubkey}}
    assert ex.submit_tx(sign_tx_dict(reg, label="alice"))["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    key_add = {"tx_type": "ACCOUNT_KEY_ADD", "signer": "alice", "nonce": 2, "payload": {"pubkey": "k:one"}}
    assert ex.submit_tx(sign_tx_dict(key_add, label="alice"))["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    ex2 = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="persist", tx_index_path=tx_index_path)
    st = ex2.read_state()
    acct = st.get("accounts", {}).get("alice", {})
    assert int(acct.get("nonce", 0)) == 2
    keys = acct.get("keys", {})
    assert isinstance(keys, dict)
    assert "k:one" in keys
