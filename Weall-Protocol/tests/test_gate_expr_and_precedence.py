# tests/test_gate_expr_and_precedence.py
from __future__ import annotations

from typing import Any

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import admit_tx
from weall.tx.canon import TxIndex


def _canon(mapping: dict[str, dict[str, Any]]) -> TxIndex:
    tx_types = []
    for i, (name, spec) in enumerate(mapping.items(), start=1):
        d = {"id": i, "name": name}
        d.update(spec)
        tx_types.append(d)

    by_name = {str(t["name"]).upper(): t for t in tx_types}
    by_id = {int(t["id"]): t for t in tx_types}
    by_id_str = {str(int(t["id"])): t for t in tx_types}
    meta: dict[str, Any] = {"generated_from": "unit"}
    return TxIndex(
        tx_types=tx_types,
        by_name=by_name,
        by_id=by_id,
        by_id_str=by_id_str,
        meta=meta,
        source_sha256="unit",
    )


@pytest.fixture(autouse=True)
def _unsigned_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")


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

    # Tier2 but not validator => deny
    ledger = LedgerView(accounts={"@user": {"poh_tier": 2, "nonce": 0}}, roles={})
    ok, rej = admit_tx(
        {"tx_type": "X", "signer": "@user", "nonce": 1, "payload": {}, "sig": "x"},
        ledger,
        canon,
        "mempool",
    )
    assert ok is False
    assert rej is not None
    assert rej.code == "gate_denied"

    # Tier3 => allow
    ledger2 = LedgerView(accounts={"@user": {"poh_tier": 3, "nonce": 0}}, roles={})
    ok2, rej2 = admit_tx(
        {"tx_type": "X", "signer": "@user", "nonce": 1, "payload": {}, "sig": "x"},
        ledger2,
        canon,
        "mempool",
    )
    assert ok2 is True
    assert rej2 is None
