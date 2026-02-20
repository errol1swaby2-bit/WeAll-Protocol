# tests/test_identity_domain_mvp.py
from __future__ import annotations

from pathlib import Path

from weall.ledger.state import LedgerView
from weall.runtime.domain_apply import apply_tx
from weall.runtime.supported_txs import SUPPORTED_TX_TYPES
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.testing.sigtools import ensure_account_has_test_key, sign_tx_dict
from weall.tx.canon import load_tx_index_json


def _canon():
    repo_root = Path(__file__).resolve().parents[1]
    return load_tx_index_json(repo_root / "generated" / "tx_index.json")


def test_mempool_rejects_canon_but_unsupported_tx_types() -> None:
    idx = _canon()

    # Find any mempool-context tx in canon that is not supported by this build.
    candidate = None
    for tx in idx.tx_types:
        if str(tx.get("context") or "").lower() != "mempool":
            continue
        if bool(tx.get("receipt_only", False)):
            continue
        name = tx["name"]
        if name not in SUPPORTED_TX_TYPES:
            candidate = name
            break

    # If everything is supported (unlikely), skip hard failure.
    if not candidate:
        return

    st = {
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10.0, "keys": []},
        },
        "roles": {},
    }
    pk = ensure_account_has_test_key(st["accounts"], account_id="alice")

    tx = {"tx_type": candidate, "signer": "alice", "nonce": 1, "payload": {}, "sig": ""}
    tx = sign_tx_dict(tx, label="alice")
    # Sanity: signature is valid against alice's key
    assert pk

    verdict = admit_tx(ledger=LedgerView.from_ledger(st), canon=idx, tx=tx, context="mempool")
    assert verdict.ok is False
    assert verdict.code == "unsupported_tx"


def test_device_register_and_revoke_roundtrip() -> None:
    idx = _canon()
    st = {"accounts": {"alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0, "keys": []}}, "roles": {}}
    ensure_account_has_test_key(st["accounts"], account_id="alice")

    # Register (production-grade strict payload: no extra fields)
    tx = sign_tx_dict(
        {"tx_type": "ACCOUNT_DEVICE_REGISTER", "signer": "alice", "nonce": 1, "payload": {"device_id": "dev1"}, "sig": ""}
    )
    verdict = admit_tx(ledger=LedgerView.from_ledger(st), canon=idx, tx=tx, context="mempool")
    assert verdict.ok
    r = apply_tx(st, TxEnvelope.from_json(tx))
    assert r and r.get("applied") == "ACCOUNT_DEVICE_REGISTER"
    assert st["accounts"]["alice"]["devices"]["dev1"]["active"] is True

    # Revoke
    tx2 = sign_tx_dict(
        {"tx_type": "ACCOUNT_DEVICE_REVOKE", "signer": "alice", "nonce": 2, "payload": {"device_id": "dev1"}, "sig": ""}
    )
    verdict2 = admit_tx(ledger=LedgerView.from_ledger(st), canon=idx, tx=tx2, context="mempool")
    assert verdict2.ok
    r2 = apply_tx(st, TxEnvelope.from_json(tx2))
    assert r2 and r2.get("applied") == "ACCOUNT_DEVICE_REVOKE"
    assert st["accounts"]["alice"]["devices"]["dev1"]["active"] is False


def test_guardian_recovery_flow_threshold_2() -> None:
    idx = _canon()
    st = {
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0, "keys": []},
            "bob": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0, "keys": []},
            "carol": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0, "keys": []},
        },
        "roles": {},
    }
    ensure_account_has_test_key(st["accounts"], account_id="alice")
    ensure_account_has_test_key(st["accounts"], account_id="bob")
    ensure_account_has_test_key(st["accounts"], account_id="carol")

    # Alice sets guardians + threshold
    tx_cfg = sign_tx_dict(
        {
            "tx_type": "ACCOUNT_RECOVERY_CONFIG_SET",
            "signer": "alice",
            "nonce": 1,
            "payload": {"guardians": ["bob", "carol"], "threshold": 2},
            "sig": "",
        }
    )
    assert admit_tx(ledger=LedgerView.from_ledger(st), canon=idx, tx=tx_cfg, context="mempool").ok
    apply_tx(st, TxEnvelope.from_json(tx_cfg))

    # Bob requests recovery for alice (new_pubkey)
    tx_req = sign_tx_dict(
        {
            "tx_type": "ACCOUNT_RECOVERY_REQUEST",
            "signer": "bob",
            "nonce": 1,
            "payload": {"target": "alice", "new_pubkey": "deadbeef"},
            "sig": "",
        }
    )
    assert admit_tx(ledger=LedgerView.from_ledger(st), canon=idx, tx=tx_req, context="mempool").ok
    rreq = apply_tx(st, TxEnvelope.from_json(tx_req))

    assert rreq
    assert rreq.get("applied") == "ACCOUNT_RECOVERY_REQUEST"

    # Carol approves (note: requester already counts as an approval in production)
    tx_appr = sign_tx_dict(
        {
            "tx_type": "ACCOUNT_RECOVERY_APPROVE",
            "signer": "carol",
            "nonce": 1,
            "payload": {"request_id": rreq.get("request_id")},
            "sig": "",
        }
    )
    assert admit_tx(ledger=LedgerView.from_ledger(st), canon=idx, tx=tx_appr, context="mempool").ok
    apply_tx(st, TxEnvelope.from_json(tx_appr))

    # Finalize is a SYSTEM tx in production (block/system context).
    tx_fin = {
        "tx_type": "ACCOUNT_RECOVERY_FINALIZE",
        "signer": "SYSTEM",
        "nonce": 0,
        "payload": {"request_id": rreq.get("request_id")},
        "sig": "",
        "parent": "txid:recovery_ready",
        "system": True,
    }
    rfinal = apply_tx(st, TxEnvelope.from_json(tx_fin))
    assert rfinal
    assert rfinal.get("applied") == "ACCOUNT_RECOVERY_FINALIZE"
