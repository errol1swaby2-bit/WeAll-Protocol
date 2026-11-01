"""PR77: block unverified severe-sanction finality at scheduler and applier.

Synthetic in-memory behavior only, not a registered severe-class source, an
authenticated SYSTEM receipt, on-chain appeals, BFT, or replay validation.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.severe_sanction_boundary import (
    is_explicit_severe_account_sanction,
)
from weall.runtime.tx_admission import TxEnvelope


def _state(*, enabled: bool, marker: str = "severity", value: str = "severe") -> dict:
    case = {
        "id": "case-1",
        "target_type": "account",
        "target_id": "@target",
        "stage": "appeal_window",
        "resolved": True,
        "resolution": {"summary": "Unverified severe decision", "actions": []},
        "appeal_deadline_height": 8,
        "appeals": [],
    }
    if marker:
        case[marker] = value
    return {
        "height": 10,
        "meta": {"constitutional_clock": {"enabled": enabled}},
        "disputes_by_id": {"case-1": case},
        "system_queue": [],
    }


def _receipt() -> TxEnvelope:
    return TxEnvelope(
        tx_type="DISPUTE_FINAL_RECEIPT",
        signer="SYSTEM",
        system=True,
        nonce=11,
        parent="case-1:synthetic",
        payload={"dispute_id": "case-1", "receipt_id": "synthetic-final"},
    )


@pytest.mark.parametrize(
    ("marker", "value"),
    [("severity", "severe"), ("severity", "critical"), ("sanction_class", "S4")],
)
def test_explicit_severe_classification_blocks_window_expiry(marker, value) -> None:
    state = _state(enabled=True, marker=marker, value=value)
    before = copy.deepcopy(state)
    assert is_explicit_severe_account_sanction(state["disputes_by_id"]["case-1"])
    assert tick_dispute_lifecycle(state, next_height=11) == 0
    assert state == before


def test_claimed_resolved_appeal_cannot_schedule_severe_final_receipt() -> None:
    state = _state(enabled=True)
    state["disputes_by_id"]["case-1"].update(
        {
            "stage": "appeal_resolved",
            "appeal_panel_result": {
                "reached": True,
                "decision": "uphold",
                "resolution": {"decision": "uphold"},
            },
        }
    )
    before = copy.deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=11) == 0
    assert state == before


@pytest.mark.parametrize(
    ("marker", "value"),
    [("severity", "severe"), ("severity", "critical"), ("sanction_class", "S4")],
)
def test_direct_system_final_receipt_cannot_bypass_unimplemented_appeal(marker, value) -> None:
    state = _state(enabled=True, marker=marker, value=value)
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        dispute.apply_dispute(state, _receipt())
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "severe_sanction_automatic_appeal_unimplemented"
    assert state == before


def test_ordinary_case_window_closure_remains_operational() -> None:
    state = _state(enabled=True, marker="", value="")
    assert tick_dispute_lifecycle(state, next_height=11) == 1
    assert state["disputes_by_id"]["case-1"]["stage"] == "finalizing"
    assert [x["tx_type"] for x in state["system_queue"]] == ["DISPUTE_FINAL_RECEIPT"]


def test_non_account_severe_case_keeps_existing_scheduler() -> None:
    state = _state(enabled=True)
    state["disputes_by_id"]["case-1"]["target_type"] = "content"
    assert not is_explicit_severe_account_sanction(state["disputes_by_id"]["case-1"])
    assert tick_dispute_lifecycle(state, next_height=11) == 1


def test_legacy_clock_severe_case_keeps_existing_final_receipt_contract() -> None:
    state = _state(enabled=False)
    result = dispute.apply_dispute(state, _receipt())
    assert result is not None
    assert result["applied"] == "DISPUTE_FINAL_RECEIPT"
    assert state["disputes_by_id"]["case-1"]["stage"] == "finalized"
    assert "synthetic-final" in state["dispute_receipts"]


def test_no_account_ban_is_emitted_as_side_effect() -> None:
    state = _state(enabled=True)
    tick_dispute_lifecycle(state, next_height=11)
    assert not state["system_queue"]
    assert "reputation" not in state
    assert "accounts" not in state
