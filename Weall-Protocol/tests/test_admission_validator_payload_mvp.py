# tests/test_admission_validator_payload_mvp.py
from __future__ import annotations

from pathlib import Path

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    canon_path = repo_root / "generated" / "tx_index.json"
    return load_tx_index_json(canon_path)


def _ledger(nonce: int) -> LedgerView:
    return LedgerView(
        accounts={
            "@alice": {
                "nonce": nonce,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": 10,
            },
        },
        roles={},
    )


def test_validator_register_requires_endpoint() -> None:
    idx = _load_index()
    ledger = _ledger(0)

    env = TxEnvelope(
        tx_type="VALIDATOR_REGISTER",
        signer="@alice",
        nonce=1,
        payload={},  # missing endpoint
        sig="deadbeef",
        parent=None,
    )
    ok, rej = admit_tx(env, ledger, idx, context="mempool")
    assert not ok
    assert rej is not None
    assert rej.code == "invalid_payload"


def test_validator_set_update_requires_active_set_list() -> None:
    idx = _load_index()
    ledger = _ledger(0)

    # Canon: block-only + receipt_only. Provide parent so we can validate payload.
    env = TxEnvelope(
        tx_type="VALIDATOR_SET_UPDATE",
        signer="@alice",
        nonce=1,
        payload={},  # missing active_set
        sig="deadbeef",
        parent="txid:parent",
        system=True,
    )
    ok, rej = admit_tx(env, ledger, idx, context="block")
    assert not ok
    assert rej is not None
    assert rej.code == "invalid_payload"
