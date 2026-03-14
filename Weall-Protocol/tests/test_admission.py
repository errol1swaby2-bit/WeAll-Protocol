# tests/test_admission.py
from __future__ import annotations

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def _load_index():
    root = _repo_root()
    return load_tx_index_json(root / "generated" / "tx_index.json")


def test_mempool_enforces_next_nonce(monkeypatch) -> None:
    # This test focuses on nonce semantics only.
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    idx = _load_index()

    # Choose a tx type that exists in the canon AND is not subject to MVP payload checks.
    # (Peer/validator payload MVP checks can cause false failures unrelated to nonce.)
    tx_type = "ACCOUNT_DEVICE_REGISTER"

    ledger = LedgerView(
        accounts={
            "@alice": {
                "nonce": 5,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10,
            },
        },
        roles={},
    )

    payload = {"device_id": "dev1", "pubkey": "k:dev1"}

    # wrong nonce (should be 6)
    env = TxEnvelope(
        tx_type=tx_type,
        signer="@alice",
        nonce=7,
        payload=payload,
        sig="deadbeef",
        parent=None,
    )
    ok, rej = admit_tx(env.to_json(), ledger, idx, context="mempool")
    assert not ok
    assert rej is not None
    assert rej.code == "bad_nonce"

    # right nonce
    env2 = TxEnvelope(
        tx_type=tx_type,
        signer="@alice",
        nonce=6,
        payload=payload,
        sig="deadbeef",
        parent=None,
    )
    ok2, rej2 = admit_tx(env2.to_json(), ledger, idx, context="mempool")
    assert ok2
    assert rej2 is None
