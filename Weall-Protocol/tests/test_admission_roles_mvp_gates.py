# tests/test_admission_roles_mvp_gates.py
from __future__ import annotations

from types import SimpleNamespace

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import admit_tx
from weall.testing.sigtools import ensure_account_has_test_key, sign_tx_dict


def _canon(entries: dict) -> SimpleNamespace:
    return SimpleNamespace(by_name=entries)


def _ledger(accounts: dict, roles: dict) -> LedgerView:
    state = {"accounts": accounts, "roles": roles}
    for aid in list(state["accounts"].keys()):
        ensure_account_has_test_key(state["accounts"], account_id=str(aid))
    return LedgerView.from_ledger(state)


def _tx(tx_type: str, signer: str, nonce: int, payload: dict) -> dict:
    tx = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "sig": "sig",  # placeholder overwritten by sign_tx_dict
        "system": False,
    }
    return sign_tx_dict(tx)


def test_treasury_create_requires_tier3plus() -> None:
    canon = _canon({"TREASURY_CREATE": {"context": "mempool", "subject_gate": "Tier3+"}})

    # Tier2 should fail
    led = _ledger(accounts={"alice": {"nonce": 0, "poh_tier": 2}}, roles={})
    v = admit_tx(ledger=led, tx=_tx("TREASURY_CREATE", "alice", 1, {"treasury_id": "t1", "name": "Treasury 1"}), canon=canon, context="mempool")
    assert v.ok is False
    assert v.code == "gate_denied"

    # Tier3 should pass
    led2 = _ledger(accounts={"alice": {"nonce": 0, "poh_tier": 3}}, roles={})
    v2 = admit_tx(ledger=led2, tx=_tx("TREASURY_CREATE", "alice", 1, {"treasury_id": "t1", "name": "Treasury 1"}), canon=canon, context="mempool")
    assert v2.ok is True


def test_treasury_signers_set_requires_scoped_signer() -> None:
    canon = _canon({"TREASURY_SIGNERS_SET": {"context": "mempool", "subject_gate": "Signer"}})

    roles = {"treasuries_by_id": {"t1": {"signers": ["alice"], "threshold": 1}}}
    led = _ledger(accounts={"alice": {"nonce": 0, "poh_tier": 3}}, roles=roles)

    ok = admit_tx(
        ledger=led,
        tx=_tx("TREASURY_SIGNERS_SET", "alice", 1, {"treasury_id": "t1", "signers": ["alice"]}),
        canon=canon,
        context="mempool",
    )
    assert ok.ok is True

    led_bad = _ledger(accounts={"bob": {"nonce": 0, "poh_tier": 3}}, roles=roles)
    bad = admit_tx(
        ledger=led_bad,
        tx=_tx("TREASURY_SIGNERS_SET", "bob", 1, {"treasury_id": "t1", "signers": ["bob"]}),
        canon=canon,
        context="mempool",
    )
    assert bad.ok is False
    assert bad.code == "gate_denied"


def test_group_signers_set_and_moderators_set_require_scoped_signer() -> None:
    canon = _canon(
        {
            "GROUP_SIGNERS_SET": {"context": "mempool", "subject_gate": "Signer"},
            "GROUP_MODERATORS_SET": {"context": "mempool", "subject_gate": "Signer"},
        }
    )

    roles = {"groups_by_id": {"g1": {"signers": ["alice"], "moderators": []}}}

    led = _ledger(accounts={"alice": {"nonce": 0, "poh_tier": 3}}, roles=roles)
    ok1 = admit_tx(
        ledger=led,
        tx=_tx("GROUP_SIGNERS_SET", "alice", 1, {"group_id": "g1", "signers": ["alice", "bob"]}),
        canon=canon,
        context="mempool",
    )
    assert ok1.ok is True

    ok2 = admit_tx(
        ledger=led,
        tx=_tx("GROUP_MODERATORS_SET", "alice", 1, {"group_id": "g1", "moderators": ["alice"]}),
        canon=canon,
        context="mempool",
    )
    assert ok2.ok is True

    led_bad = _ledger(accounts={"bob": {"nonce": 0, "poh_tier": 3}}, roles=roles)
    bad = admit_tx(
        ledger=led_bad,
        tx=_tx("GROUP_MODERATORS_SET", "bob", 1, {"group_id": "g1", "moderators": ["bob"]}),
        canon=canon,
        context="mempool",
    )
    assert bad.ok is False
    assert bad.code == "gate_denied"
