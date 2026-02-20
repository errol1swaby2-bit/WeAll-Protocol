from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair, sign_tx_dict


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_nonce_consumed_when_apply_rejects(tmp_path: Path, monkeypatch) -> None:
    """Policy B nonce semantics:

    - nonce=2 tx is included but rejected during apply
    - nonce=2 is still consumed
    - then nonce=3 tx can be admitted and applied
    """
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="nonce-reject", tx_index_path=tx_index_path)

    alice_pubkey, _ = deterministic_ed25519_keypair(label="alice")

    # Register with seed pubkey so signature verification can succeed for future txs.
    reg = {"tx_type": "ACCOUNT_REGISTER", "signer": "alice", "nonce": 1, "payload": {"pubkey": alice_pubkey}}
    assert ex.submit_tx(sign_tx_dict(reg, label="alice"))["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    # Bad tx (missing pubkey) should be admitted (signed) and INCLUDED,
    # but rejected during apply. Policy B should still consume nonce=2.
    bad = {"tx_type": "ACCOUNT_KEY_ADD", "signer": "alice", "nonce": 2, "payload": {}}
    assert ex.submit_tx(sign_tx_dict(bad, label="alice"))["ok"] is True
    assert ex.produce_block(max_txs=10).ok is True

    # Now nonce=3 is the next valid tx for mempool admission.
    good = {"tx_type": "ACCOUNT_KEY_ADD", "signer": "alice", "nonce": 3, "payload": {"pubkey": "k:test"}}
    assert ex.submit_tx(sign_tx_dict(good, label="alice"))["ok"] is True
    assert ex.produce_block(max_txs=10).ok is True

    st = ex.read_state()
    acct = st.get("accounts", {}).get("alice", {})
    assert int(acct.get("nonce", 0)) == 3
    keys = acct.get("keys", {})
    assert isinstance(keys, dict)
    assert "k:test" in keys
