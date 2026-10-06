from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury
from weall.runtime.gate_expr import eval_gate
from weall.runtime.tx_admission_types import TxEnvelope


def _env(signer: str, *, treasury_id: str = "t1", spend_id: str = "s1") -> TxEnvelope:
    return TxEnvelope(
        tx_type="TREASURY_SPEND_CANCEL",
        signer=signer,
        nonce=1,
        system=False,
        payload={"treasury_id": treasury_id, "spend_id": spend_id},
    )


def _state(*, include_snapshot: bool = True) -> dict:
    spend = {
        "spend_id": "s1",
        "treasury_id": "t1",
        "status": "proposed",
    }
    if include_snapshot:
        spend["allowed_signers"] = ["@scoped"]

    return {
        "accounts": {
            "@scoped": {"poh_tier": 2, "banned": False, "locked": False},
            "@global": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {
            "emissaries": {
                "seated": ["@global"],
                "by_id": {"@global": {"active": True}},
            },
            "treasuries_by_id": {
                "t1": {
                    "signers": ["@scoped"],
                    "threshold": 1,
                    "require_emissary_signers": False,
                }
            },
        },
        "treasury": {"spends": {"s1": spend}},
    }


def _canon_cancel_entry() -> dict:
    path = Path(__file__).resolve().parents[1] / "specs" / "tx_canon" / "tx_canon.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = doc.get("txs") if isinstance(doc, dict) else doc
    assert isinstance(entries, list)
    return next(row for row in entries if row.get("name") == "TREASURY_SPEND_CANCEL")


def test_a10_f004_cancel_canon_is_treasury_scoped_signer() -> None:
    entry = _canon_cancel_entry()
    assert entry["origin"] == "USER"
    assert entry["context"] == "mempool"
    assert entry["gate"] == "Signer"


def test_a10_f004_global_emissary_outside_treasury_scope_fails_admission_gate() -> None:
    state = _state()
    ok, _meta = eval_gate(
        "Signer",
        signer="@global",
        ledger=state,
        payload={"treasury_id": "t1", "spend_id": "s1"},
        tx_type="TREASURY_SPEND_CANCEL",
    )
    assert ok is False

    scoped, _meta = eval_gate(
        "Signer",
        signer="@scoped",
        ledger=state,
        payload={"treasury_id": "t1", "spend_id": "s1"},
        tx_type="TREASURY_SPEND_CANCEL",
    )
    assert scoped is True


def test_a10_f004_apply_repeats_scoped_authorization_before_mutation() -> None:
    state = _state()

    with pytest.raises(TreasuryApplyError, match="not_authorized_signer") as caught:
        apply_treasury(state, _env("@global"))

    assert caught.value.reason == "not_authorized_signer"
    assert state["treasury"]["spends"]["s1"]["status"] == "proposed"
    assert "canceled_by" not in state["treasury"]["spends"]["s1"]

    receipt = apply_treasury(state, _env("@scoped"))
    assert receipt == {
        "applied": "TREASURY_SPEND_CANCEL",
        "spend_id": "s1",
        "deduped": False,
    }
    assert state["treasury"]["spends"]["s1"]["status"] == "canceled"
    assert state["treasury"]["spends"]["s1"]["canceled_by"] == "@scoped"


def test_a10_f004_legacy_spend_without_snapshot_derives_scoped_authority() -> None:
    state = _state(include_snapshot=False)

    with pytest.raises(TreasuryApplyError, match="not_authorized_signer"):
        apply_treasury(state, _env("@global"))

    spend = state["treasury"]["spends"]["s1"]
    assert spend["status"] == "proposed"
    assert spend["allowed_signers"] == ["@scoped"]
