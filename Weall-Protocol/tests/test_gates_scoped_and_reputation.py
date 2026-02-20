# tests/test_gates_scoped_and_reputation.py
from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import admit_tx
from weall.testing.sigtools import ensure_account_has_test_key, sign_tx_dict


def _canon(entries: dict) -> SimpleNamespace:
    return SimpleNamespace(by_name=entries)


def _ledger_view(accounts: dict, roles: dict) -> LedgerView:
    """Build a LedgerView with test keys so signature checks behave like production."""
    st = {"accounts": accounts, "roles": roles}
    for aid, acct in st["accounts"].items():
        acct.setdefault("banned", False)
        acct.setdefault("locked", False)
        acct.setdefault("reputation", 0.0)
        acct.setdefault("poh_tier", 0)
        acct.setdefault("nonce", 0)
        acct.setdefault("keys", [])
        ensure_account_has_test_key(st["accounts"], account_id=str(aid))
    return LedgerView.from_ledger(st)


def _mk_signed_tx(*, tx_type: str, signer: str, nonce: int, payload: dict) -> dict:
    return sign_tx_dict(
        {
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload,
            "sig": "",
            "system": False,
        },
        label=signer,
    )


@pytest.mark.parametrize(
    "min_rep_value,have_rep,should_pass",
    [
        (0.0, 0.0, True),
        (0.01, 0.0, False),
        (0.01, 0.009, False),
        (0.01, 0.01, True),
        # Admission treats values in [1.0, 100.0] as percentages.
        (100.0, 0.99, False),
        (100.0, 1.0, True),
    ],
)
def test_min_reputation_enforced(min_rep_value: float, have_rep: float, should_pass: bool) -> None:
    canon = _canon(
        {
            "CONTENT_POST_CREATE": {
                "context": "mempool",
                "subject_gate": "Tier0+",
                "min_reputation": min_rep_value,
            }
        }
    )

    ledger = _ledger_view(
        accounts={"alice": {"nonce": 0, "reputation": have_rep, "poh_tier": 3}},
        roles={},
    )

    tx = _mk_signed_tx(
        tx_type="CONTENT_POST_CREATE",
        signer="alice",
        nonce=1,
        payload={"post_id": "p1", "body": "hi"},
    )
    verdict = admit_tx(ledger=ledger, tx=tx, canon=canon, context="mempool")

    assert verdict.ok is should_pass, verdict
    if not should_pass:
        assert verdict.code == "reputation_too_low"


def test_banned_overrides_gate_and_reputation() -> None:
    canon = _canon(
        {
            "CONTENT_POST_CREATE": {
                "context": "mempool",
                "subject_gate": "Tier0+",
                "min_reputation": 0.01,
            }
        }
    )

    ledger = _ledger_view(
        accounts={"alice": {"nonce": 0, "reputation": 1.0, "poh_tier": 3, "banned": True}},
        roles={},
    )

    tx = _mk_signed_tx(
        tx_type="CONTENT_POST_CREATE",
        signer="alice",
        nonce=1,
        payload={"post_id": "p1", "body": "hi"},
    )
    verdict = admit_tx(ledger=ledger, tx=tx, canon=canon, context="mempool")

    assert verdict.ok is False
    assert verdict.code == "gate_denied"


def test_locked_overrides_gate_and_reputation() -> None:
    canon = _canon(
        {
            "CONTENT_POST_CREATE": {
                "context": "mempool",
                "subject_gate": "Tier0+",
                "min_reputation": 0.01,
            }
        }
    )

    ledger = _ledger_view(
        accounts={"alice": {"nonce": 0, "reputation": 1.0, "poh_tier": 3, "locked": True}},
        roles={},
    )

    tx = _mk_signed_tx(
        tx_type="CONTENT_POST_CREATE",
        signer="alice",
        nonce=1,
        payload={"post_id": "p1", "body": "hi"},
    )
    verdict = admit_tx(ledger=ledger, tx=tx, canon=canon, context="mempool")

    assert verdict.ok is False
    assert verdict.code == "gate_denied"
