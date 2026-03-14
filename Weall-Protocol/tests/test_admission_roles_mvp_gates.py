# tests/test_admission_roles_mvp_gates.py
from __future__ import annotations

from typing import Any, Dict

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import admit_tx
from weall.tx.canon import TxIndex


def _canon(mapping: Dict[str, Dict[str, Any]]) -> TxIndex:
    tx_types = []
    for i, (name, spec) in enumerate(mapping.items(), start=1):
        d = {"id": i, "name": name}
        d.update(spec)
        tx_types.append(d)

    by_name = {str(t["name"]).upper(): t for t in tx_types}
    by_id = {int(t["id"]): t for t in tx_types}
    by_id_str = {str(int(t["id"])): t for t in tx_types}
    meta: Dict[str, Any] = {"generated_from": "unit"}
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
    # These tests validate gating logic, not crypto.
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")


def test_treasury_create_requires_tier3plus() -> None:
    canon = _canon({"TREASURY_CREATE": {"context": "mempool", "subject_gate": "Tier3+"}})

    # Tier2 => denied
    ledger = LedgerView(accounts={"@user": {"poh_tier": 2, "nonce": 0}}, roles={})
    ok, rej = admit_tx(
        {
            "tx_type": "TREASURY_CREATE",
            "signer": "@user",
            "nonce": 1,
            "payload": {"treasury_id": "t1"},
            "sig": "x",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert ok is False
    assert rej is not None
    assert rej.code == "gate_denied"

    # Tier3 => allowed
    ledger2 = LedgerView(accounts={"@user": {"poh_tier": 3, "nonce": 0}}, roles={})
    ok2, rej2 = admit_tx(
        {
            "tx_type": "TREASURY_CREATE",
            "signer": "@user",
            "nonce": 1,
            "payload": {"treasury_id": "t1"},
            "sig": "x",
        },
        ledger2,
        canon,
        context="mempool",
    )
    assert ok2 is True
    assert rej2 is None


def test_treasury_signers_set_requires_scoped_signer() -> None:
    canon = _canon({"TREASURY_SIGNERS_SET": {"context": "mempool", "subject_gate": "Signer"}})

    # No signer role => denied.
    ledger = LedgerView(accounts={"@user": {"poh_tier": 3, "nonce": 0}}, roles={})
    ok, rej = admit_tx(
        {
            "tx_type": "TREASURY_SIGNERS_SET",
            "signer": "@user",
            "nonce": 1,
            "payload": {"treasury_id": "t1", "signers": ["@user"]},
            "sig": "x",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert ok is False
    assert rej is not None
    assert rej.code == "gate_denied"


def test_group_signers_set_and_moderators_set_require_scoped_signer() -> None:
    canon = _canon(
        {
            "GROUP_SIGNERS_SET": {"context": "mempool", "subject_gate": "Signer"},
            "GROUP_MODERATORS_SET": {"context": "mempool", "subject_gate": "Signer"},
        }
    )

    ledger = LedgerView(accounts={"@user": {"poh_tier": 3, "nonce": 0}}, roles={})

    ok1, rej1 = admit_tx(
        {
            "tx_type": "GROUP_SIGNERS_SET",
            "signer": "@user",
            "nonce": 1,
            "payload": {"group_id": "g1", "signers": ["@user"]},
            "sig": "x",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert ok1 is False
    assert rej1 is not None
    assert rej1.code == "gate_denied"

    ok2, rej2 = admit_tx(
        {
            "tx_type": "GROUP_MODERATORS_SET",
            "signer": "@user",
            "nonce": 1,
            "payload": {"group_id": "g1", "moderators": ["@user"]},
            "sig": "x",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert ok2 is False
    assert rej2 is not None
    assert rej2.code == "gate_denied"
