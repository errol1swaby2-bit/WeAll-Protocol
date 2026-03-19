# tests/test_gates_scoped_and_reputation.py
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
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")


@pytest.mark.parametrize(
    "spec_fragment,have_rep_units,should_pass",
    [
        ({"min_reputation": 0.0}, 0, True),
        ({"min_reputation": 0.01}, 0, False),
        ({"min_reputation": 0.01}, 9, False),
        ({"min_reputation": 0.01}, 10, True),
        # Admission treats values in [1.0, 100.0] as percentages.
        ({"min_reputation": 100.0}, 990, False),
        ({"min_reputation": 100.0}, 1000, True),
        ({"min_reputation_milli": 1250}, 1249, False),
        ({"min_reputation_milli": 1250}, 1250, True),
    ],
)
def test_min_reputation_enforced(spec_fragment: Dict[str, Any], have_rep_units: int, should_pass: bool) -> None:
    canon = _canon(
        {
            "CONTENT_POST_CREATE": {
                "context": "mempool",
                "subject_gate": "Tier0+",
                **spec_fragment,
            }
        }
    )

    ledger = LedgerView(
        accounts={
            "@user": {
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation_milli": have_rep_units,
                "reputation": have_rep_units / 1000.0,
                "nonce": 0,
            }
        },
        roles={},
    )

    ok, _rej = admit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@user",
            "nonce": 1,
            "payload": {"post_id": "p1", "body": "hello"},
            "sig": "x",
        },
        ledger,
        canon,
        context="mempool",
    )

    assert ok is should_pass


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

    ledger = LedgerView(
        accounts={"@user": {"poh_tier": 3, "banned": True, "locked": False, "reputation": 1.0, "nonce": 0}},
        roles={},
    )
    ok, rej = admit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@user",
            "nonce": 1,
            "payload": {"post_id": "p1", "body": "hello"},
            "sig": "x",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert ok is False
    assert rej is not None
    assert rej.code == "gate_denied"
    assert rej.reason == "banned"


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

    ledger = LedgerView(
        accounts={"@user": {"poh_tier": 3, "banned": False, "locked": True, "reputation": 1.0, "nonce": 0}},
        roles={},
    )
    ok, rej = admit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@user",
            "nonce": 1,
            "payload": {"post_id": "p1", "body": "hello"},
            "sig": "x",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert ok is False
    assert rej is not None
    assert rej.code == "gate_denied"
    assert rej.reason == "locked"
