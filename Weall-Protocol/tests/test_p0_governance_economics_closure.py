from __future__ import annotations

import pytest

from weall.runtime.apply import economics as economics_apply
from weall.runtime.apply.governance import _apply_gov_proposal_edit
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def test_strict_production_proposal_cannot_be_edited_after_voting_opens() -> None:
    """A09-F003: existing ballots must authorize an immutable proposal object."""

    state = {
        "chain_id": "weall-prod",
        "gov_proposals_by_id": {
            "proposal-1": {
                "proposal_id": "proposal-1",
                "creator": "@alice",
                "stage": "voting",
                "title": "approved title",
                "body": "approved body",
                "actions": [{"type": "PARAM_SET", "key": "example", "value": 1}],
                "rules": {},
                "versions": [{"version": 1, "title": "approved title"}],
                "current_version": 1,
                "frozen_version": 1,
            }
        },
    }
    env = TxEnvelope(
        tx_type="GOV_PROPOSAL_EDIT",
        signer="@alice",
        nonce=2,
        payload={"proposal_id": "proposal-1", "title": "replacement title"},
        chain_id="weall-prod",
    )

    with pytest.raises(ApplyError) as exc_info:
        _apply_gov_proposal_edit(state, env)

    assert exc_info.value.code == "forbidden"
    assert exc_info.value.message == "proposal_frozen_for_voting"
    assert state["gov_proposals_by_id"]["proposal-1"]["title"] == "approved title"


def test_production_economics_enable_always_checks_activation_preconditions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A10-F002: `weall-prod` readiness checks are not caller-optional."""

    calls: list[dict] = []

    monkeypatch.setattr(economics_apply, "_require_system_env", lambda env: None)
    monkeypatch.setattr(economics_apply, "_wrap_time_lock", lambda state: None)

    def require_preconditions(state: dict) -> dict:
        calls.append(state)
        return {"ready": True, "checked": True}

    monkeypatch.setattr(
        economics_apply,
        "_require_activation_preconditions",
        require_preconditions,
    )

    state = {
        "chain_id": "weall-prod",
        "params": {
            "economics_enabled": False,
            "economics_activation_preconditions_required": False,
        },
    }
    env = TxEnvelope(
        tx_type="ECONOMICS_ACTIVATION",
        signer="SYSTEM",
        nonce=0,
        payload={"enable": True, "enforce_preconditions": False},
        system=True,
        chain_id="weall-prod",
    )

    result = economics_apply._apply_economics_activation(state, env)

    assert calls == [state]
    assert result["enabled"] is True
    assert state["params"]["economics_enabled"] is True
    assert state["economics"]["activation_preconditions"] == {
        "ready": True,
        "checked": True,
    }
