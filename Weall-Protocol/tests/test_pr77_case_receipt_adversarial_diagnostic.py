"""Source-bound CASE handler diagnostics, not acceptance of unsafe behavior.

These tests deliberately detect current fail-open surfaces in direct synthetic
handler calls. A passing diagnostic means a known HOLD was reproduced, not that
canonical admission, rollback, or historical replay is safe.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, payload: dict, *, nonce: int = 1, system: bool = True) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM",
        nonce=nonce,
        system=system,
        sig="synthetic-not-validated",
        payload=payload,
    )


def test_case_receipt_rejects_non_system_envelope_before_direct_state_mutation() -> None:
    state: dict = {}
    before = copy.deepcopy(state)
    with pytest.raises(DisputeApplyError) as failure:
        apply_dispute(
            state,
            _env("CASE_TYPE_REGISTER", {"case_type": "public-report"}, system=False),
        )
    assert (failure.value.code, failure.value.reason) == ("forbidden", "system_only")
    assert state == before


def test_case_type_registration_records_first_system_receipt() -> None:
    state: dict = {}
    payload = {"case_type": "public-report"}
    receipt = apply_dispute(state, _env("CASE_TYPE_REGISTER", payload))
    assert receipt == {
        "applied": "CASE_TYPE_REGISTER",
        "case_type": "public-report",
        "receipt": True,
    }
    assert state["cases"]["types"]["public-report"]["payload"] == payload


def test_hold_conflicting_case_binding_receipt_can_disagree_with_stored_state() -> None:
    """KNOWN HOLD: not an approval of duplicate-binding or scheduler authority."""
    state: dict = {}
    original = {"case_id": "case-a", "dispute_id": "dispute-original"}
    conflicting = {"case_id": "case-a", "dispute_id": "dispute-conflicting"}
    first = apply_dispute(state, _env("CASE_BIND_TO_DISPUTE", original, nonce=10))
    second = apply_dispute(state, _env("CASE_BIND_TO_DISPUTE", conflicting, nonce=11))
    stored = state["cases"]["bindings"]["case-a"]
    assert first["dispute_id"] == stored["dispute_id"] == "dispute-original"
    assert second["receipt"] is True
    assert second["dispute_id"] == "dispute-conflicting"
    assert second["dispute_id"] != stored["dispute_id"]


@pytest.mark.parametrize(
    ("tx_type", "reason"),
    [
        ("CASE_TYPE_REGISTER", "missing_case_type"),
        ("CASE_BIND_TO_DISPUTE", "missing_dispute_id"),
    ],
)
def test_hold_required_field_rejection_mutates_uninitialized_direct_state(
    tx_type: str, reason: str
) -> None:
    """KNOWN HOLD: the real rollback path requires separate fail-atomic proof."""
    state: dict = {}
    before = copy.deepcopy(state)
    with pytest.raises(DisputeApplyError) as failure:
        apply_dispute(state, _env(tx_type, {}, nonce=10))
    assert (failure.value.code, failure.value.reason) == ("invalid_payload", reason)
    assert state != before
    assert state["cases"] == {"types": {}, "bindings": {}, "outcomes": []}
