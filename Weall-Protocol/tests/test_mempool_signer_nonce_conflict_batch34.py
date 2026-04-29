from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, *, chain_id: str) -> WeAllExecutor:
    root = _repo_root()
    return WeAllExecutor(
        db_path=str(tmp_path / f"{chain_id}.db"),
        node_id="v1",
        chain_id=chain_id,
        tx_index_path=str(root / "generated" / "tx_index.json"),
    )


def test_mempool_rejects_conflicting_same_signer_nonce_batch34(tmp_path: Path) -> None:
    ex = _executor(tmp_path, chain_id="batch34-conflict")

    tx1 = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": "k:alice:1"},
    }
    tx2 = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": "k:alice:DIFFERENT"},
    }

    r1 = ex.submit_tx(tx1)
    r2 = ex.submit_tx(tx2)

    assert r1.get("ok") is True
    assert r2.get("ok") is False
    assert r2.get("error") == "mempool_signer_nonce_conflict"
    assert r2.get("details", {}).get("signer") == "@alice"
    assert int(r2.get("details", {}).get("nonce")) == 1
    mp = ex.read_mempool()
    assert len(mp) == 1
    assert mp[0].get("payload", {}).get("pubkey") == "k:alice:1"


def test_mempool_duplicate_same_signer_nonce_same_payload_rejected_deterministically_batch34(tmp_path: Path) -> None:
    ex = _executor(tmp_path, chain_id="batch34-idempotent")

    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@bob",
        "nonce": 1,
        "payload": {"pubkey": "k:bob:1"},
    }

    r1 = ex.submit_tx(dict(tx))
    r2 = ex.submit_tx(dict(tx))

    assert r1.get("ok") is True
    assert r2.get("ok") is False
    assert r2.get("error") == "tx_id_conflict"
    assert ex.mempool.size() == 1


def test_mempool_allows_corrected_retry_after_removal_batch34(tmp_path: Path) -> None:
    ex = _executor(tmp_path, chain_id="batch34-retry")

    bad = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@carol",
        "nonce": 1,
        "payload": {"pubkey": "k:carol:bad"},
    }
    good = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@carol",
        "nonce": 1,
        "payload": {"pubkey": "k:carol:good"},
    }

    first = ex.submit_tx(dict(bad))
    assert first.get("ok") is True

    conflict = ex.submit_tx(dict(good))
    assert conflict.get("ok") is False
    assert conflict.get("error") == "mempool_signer_nonce_conflict"

    removed = ex.mempool.remove(str(first.get("tx_id") or ""))
    assert removed.get("ok") is True

    retry = ex.submit_tx(dict(good))
    assert retry.get("ok") is True
    mp = ex.read_mempool()
    assert len(mp) == 1
    assert mp[0].get("payload", {}).get("pubkey") == "k:carol:good"


def test_mempool_conflict_rule_persists_across_restart_batch34(tmp_path: Path) -> None:
    ex = _executor(tmp_path, chain_id="batch34-restart")
    accepted = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@dave",
            "nonce": 1,
            "payload": {"pubkey": "k:dave:1"},
        }
    )
    assert accepted.get("ok") is True

    ex2 = _executor(tmp_path, chain_id="batch34-restart")
    conflict = ex2.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@dave",
            "nonce": 1,
            "payload": {"pubkey": "k:dave:other"},
        }
    )
    assert conflict.get("ok") is False
    assert conflict.get("error") == "mempool_signer_nonce_conflict"
    assert ex2.mempool.size() == 1

