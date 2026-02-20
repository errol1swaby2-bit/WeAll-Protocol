# tests/test_gate_expr_and_precedence.py
from __future__ import annotations

from types import SimpleNamespace

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import admit_tx
from weall.testing.sigtools import ensure_account_has_test_key, sign_tx_dict


def _canon(entries: dict) -> SimpleNamespace:
    return SimpleNamespace(by_name=entries)


def _ledger(*, tier: int, nonce: int = 0) -> LedgerView:
    state = {
        "accounts": {"alice": {"nonce": nonce, "poh_tier": tier}},
        "roles": {"validators": {"active_set": ["alice"]}},
    }
    ensure_account_has_test_key(state["accounts"], account_id="alice")
    return LedgerView.from_ledger(state)


def _tx(*, tx_type: str, nonce: int, gate_payload: dict | None = None) -> dict:
    tx = {
        "tx_type": tx_type,
        "signer": "alice",
        "nonce": nonce,
        "payload": gate_payload or {},
        "sig": "sig",
    }
    return sign_tx_dict(tx)


def test_and_binds_tighter_than_or() -> None:
    # Expression: Tier3+ | Tier2+ & Validator
    # Meaning: Tier3+ OR (Tier2+ AND Validator)
    canon = _canon(
        {
            "X": {
                "context": "mempool",
                "subject_gate": "Tier3+ | Tier2+ & Validator",
            }
        }
    )

    # Tier2 and validator -> should pass due to second branch (Tier2+ & Validator)
    ledger = _ledger(tier=2)
    verdict = admit_tx(ledger=ledger, tx=_tx(tx_type="X", nonce=1), canon=canon, context="mempool")
    assert verdict.ok is True, verdict

    # Tier2 but NOT validator -> should fail if precedence is correct
    state2 = {"accounts": {"alice": {"nonce": 0, "poh_tier": 2}}, "roles": {}}
    ensure_account_has_test_key(state2["accounts"], account_id="alice")
    ledger2 = LedgerView.from_ledger(state2)
    verdict2 = admit_tx(ledger=ledger2, tx=_tx(tx_type="X", nonce=1), canon=canon, context="mempool")
    assert verdict2.ok is False, verdict2
    assert verdict2.code == "gate_denied"
