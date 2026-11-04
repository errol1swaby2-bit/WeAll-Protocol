"""Severe-sanction fail-closed constraints for dispute ACCOUNT_BAN.

This suite intentionally DOES NOT treat account-ban production as implemented.
It proves the ordinary/appeal-finalization enforcement allowlist cannot be
accidentally expanded to enable ACCOUNT_BAN.  Independent severe-sanction
review, automatic fresh appeal, authorization, and source compatibility remain
NO-GO requirements.  All fixtures are synthetic; there is no node launch.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.tx_admission import TxEnvelope


def _ban_action() -> dict:
    return {
        "tx_type": "ACCOUNT_BAN",
        "payload": {"account_id": "@target", "reason": "unverified_severe_sanction"},
    }


def _state() -> dict:
    return {
        "height": 10,
        "accounts": {"@target": {"banned": False}},
        "reputation": {"bans": {}},
        "disputes_by_id": {
            "case-1": {
                "id": "case-1",
                "dispute_id": "case-1",
                "target_type": "account",
                "target_id": "@target",
                "stage": "review",
                "appeals": [],
            }
        },
        "system_queue": [],
    }


def _env(tx_type: str, resolution: dict, *, nonce: int = 11) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM",
        nonce=nonce,
        system=True,
        parent="case-1:synthetic",
        payload={"dispute_id": "case-1", "resolution": resolution, "_due_height": 11},
    )


def _assert_no_ban(state: dict) -> None:
    assert state["accounts"]["@target"]["banned"] is False
    assert state["reputation"]["bans"] == {}
    assert not any(
        isinstance(item, dict) and item.get("tx_type") == "ACCOUNT_BAN"
        for item in state.get("system_queue", [])
    )


def test_severe_ban_is_rejected_even_if_allowlist_is_accidentally_expanded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dispute,
        "_ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES",
        dispute._ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES | {"ACCOUNT_BAN"},
    )
    state = _state()
    actions = dispute._validate_dispute_enforcement_actions(
        state,
        actions=[_ban_action()],
        dispute_id="case-1",
        parent_ref="synthetic-parent",
    )
    assert actions == []
    assert state["dispute_enforcement_rejections"] == [
        {
            "dispute_id": "case-1",
            "index": 0,
            "tx_type": "ACCOUNT_BAN",
            "reason": "unsupported_enforcement_action",
            "parent": "synthetic-parent",
        }
    ]
    _assert_no_ban(state)


def test_ordinary_dispute_resolution_cannot_enqueue_ban_after_allowlist_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dispute,
        "_ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES",
        dispute._ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES | {"ACCOUNT_BAN"},
    )
    state = _state()
    result = dispute.apply_dispute(
        state, _env("DISPUTE_RESOLVE", {"summary": "ban", "actions": [_ban_action()]})
    )
    assert result is not None
    assert result["enforcement_applied"] == []
    assert result["enforcement_queued"] == []
    assert any(
        row.get("tx_type") == "ACCOUNT_BAN"
        and row.get("reason") == "unsupported_enforcement_action"
        for row in state["dispute_enforcement_rejections"]
    )
    _assert_no_ban(state)


@pytest.mark.parametrize("decision", ["none", "uphold", "reverse"])
def test_final_receipt_cannot_enforce_ban_without_severe_sanction_protocol(
    monkeypatch: pytest.MonkeyPatch, decision: str
) -> None:
    monkeypatch.setattr(
        dispute,
        "_ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES",
        dispute._ALLOWED_DISPUTE_ENFORCEMENT_TX_TYPES | {"ACCOUNT_BAN"},
    )
    state = _state()
    resolution = {"summary": "case decision", "actions": [_ban_action()]}
    state["disputes_by_id"]["case-1"]["resolution"] = copy.deepcopy(resolution)
    if decision == "uphold":
        state["disputes_by_id"]["case-1"]["appeals"] = [{"by": "@target"}]
        state["disputes_by_id"]["case-1"]["appeal_panel_result"] = {
            "reached": True,
            "decision": "uphold",
            "resolution": {"decision": "uphold"},
        }
    elif decision == "reverse":
        state["disputes_by_id"]["case-1"]["appeals"] = [{"by": "@target"}]
        state["disputes_by_id"]["case-1"]["appeal_panel_result"] = {
            "reached": True,
            "decision": "reverse",
            "resolution": {"decision": "reverse"},
        }
    meta = dispute.apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", resolution, nonce=12))
    assert meta is not None
    assert meta["enforcement_applied"] == []
    _assert_no_ban(state)
    # A reversed outcome must never produce even a rejection for the removed ban.
    if decision == "reverse":
        assert not any(
            x.get("tx_type") == "ACCOUNT_BAN"
            for x in state.get("dispute_enforcement_rejections", [])
        )
    else:
        assert any(
            x.get("tx_type") == "ACCOUNT_BAN"
            for x in state.get("dispute_enforcement_rejections", [])
        )
