"""Issue #72: versioned, state-rooted operative reputation role-gate parity."""

from __future__ import annotations

import copy
import json

import pytest

from weall.runtime.apply.roles import RolesApplyError, _require_role_activation_eligible
from weall.runtime.reputation_events import (
    append_reputation_event,
    append_reputation_reversal_event,
)
from weall.runtime.reputation_matrix import derive_reputation_matrix
from weall.runtime.reputation_role_gate import (
    operative_role_reputation_preview,
    role_activation_reputation_decision,
)


def _state(*, version: int | None = None) -> dict:
    state = {
        "height": 21,
        "accounts": {
            "@alice": {
                "poh_tier": 2,
                "locked": False,
                "banned": False,
                "reputation": "6",
                "reputation_milli": 6000,
            }
        },
    }
    if version is not None:
        state["params"] = {"reputation_role_gate_version": version}
    return state


def _validator_penalty(state: dict) -> dict:
    return append_reputation_event(
        state,
        actor_id="@alice",
        event_code="VALIDATOR_DOUBLE_SIGN",
        source_flow="validator",
        source_tx_id="validator:slash-1",
        source_object_id="block-1",
        occurred_at_block=21,
    )


def test_absent_version_preserves_legacy_operative_gate_despite_event_penalty() -> None:
    state = _state()
    _validator_penalty(state)
    before = json.dumps(state, sort_keys=True)
    result = role_activation_reputation_decision(
        state, "@alice", role="validator", minimum_reputation_milli=5000
    )
    assert result["gate_version"] == 1
    assert result["eligible"] is True
    assert result["canonical_eligible"] is False
    assert result["canonical_enforcement"] is False
    assert _require_role_activation_eligible(
        state, "@alice", role="validator", minimum_reputation_milli=5000
    ) is state["accounts"]["@alice"]
    assert json.dumps(state, sort_keys=True) == before


def test_explicit_v2_requires_canonical_validator_eligibility_and_no_mutation() -> None:
    state = _state(version=2)
    _validator_penalty(state)
    before = json.dumps(state, sort_keys=True)
    decision = role_activation_reputation_decision(
        state, "@alice", role="validator", minimum_reputation_milli=5000
    )
    assert decision["canonical_enforcement"] is True
    assert decision["reason"] == "canonical_role_reputation_ineligible"
    assert decision["canonical_eligible"] is False
    with pytest.raises(RolesApplyError) as exc:
        _require_role_activation_eligible(
            state, "@alice", role="validator", minimum_reputation_milli=5000
        )
    assert exc.value.reason == decision["reason"]
    assert json.dumps(state, sort_keys=True) == before


def test_juror_reversal_and_reversal_of_reversal_are_applied_only_to_juror() -> None:
    state = _state(version=2)
    negative = append_reputation_event(
        state,
        actor_id="@alice",
        event_code="DISPUTE_JUROR_TIMED_OUT",
        source_flow="dispute",
        source_tx_id="timeout-1",
        source_object_id="case-1",
        occurred_at_block=21,
    )
    blocked = role_activation_reputation_decision(state, "@alice", role="juror")
    assert blocked["eligible"] is False
    assert role_activation_reputation_decision(
        state, "@alice", role="validator", minimum_reputation_milli=5000
    )["eligible"] is True
    correction = append_reputation_reversal_event(
        state,
        original_event_id=negative["event_id"],
        source_tx_id="appeal-1",
        occurred_at_block=22,
    )
    assert role_activation_reputation_decision(state, "@alice", role="juror")["eligible"] is True
    append_reputation_reversal_event(
        state,
        original_event_id=correction["event_id"],
        source_tx_id="appeal-2",
        occurred_at_block=23,
    )
    assert role_activation_reputation_decision(state, "@alice", role="juror")["eligible"] is False


@pytest.mark.parametrize(
    ("change", "role", "expected"),
    [
        ({"banned": True}, "juror", "account_restricted"),
        ({"locked": True}, "juror", "account_restricted"),
        ({"poh_tier": 1}, "juror", "live_verification_required"),
        ({"reputation_milli": 1000}, "validator", "reputation_insufficient"),
    ],
)
def test_independent_restrictions_are_never_bypassed(
    change: dict, role: str, expected: str
) -> None:
    state = _state(version=2)
    state["accounts"]["@alice"].update(change)
    result = role_activation_reputation_decision(
        state, "@alice", role=role, minimum_reputation_milli=5000 if role == "validator" else 0
    )
    assert result["eligible"] is False
    assert result["reason"] == expected


def test_explicit_false_like_revocation_preserves_legacy_behavior() -> None:
    state = _state(version=2)
    state["reputation"] = {"role_eligibility": {"@alice": {"roles": {"ROLE_JUROR": 0}}}}
    result = role_activation_reputation_decision(state, "@alice", role="juror")
    assert result["reason"] == "role_eligibility_revoked"


def test_v2_does_not_alias_node_operator_or_emissary_to_validator_penalties() -> None:
    state = _state(version=2)
    _validator_penalty(state)
    for role in ("node_operator", "emissary", "gov_executor"):
        result = role_activation_reputation_decision(state, "@alice", role=role)
        assert result["canonical_role"] is None
        assert result["canonical_enforcement"] is False
        assert result["eligible"] is True


@pytest.mark.parametrize("version", [-1, 0, 3, "2", True])
def test_unknown_or_malformed_version_fails_closed(version: object) -> None:
    state = _state()
    state["params"] = {"reputation_role_gate_version": version}
    result = role_activation_reputation_decision(state, "@alice", role="juror")
    assert result["gate_version"] == -1
    assert result["reason"] == "policy_unknown"


def test_matrix_reports_canonical_and_operative_separately_without_mutation() -> None:
    state = _state()
    _validator_penalty(state)
    before = copy.deepcopy(state)
    matrix = derive_reputation_matrix(state, "@alice")
    preview = operative_role_reputation_preview(state, "@alice")
    assert preview == matrix["operative_role_activation"]
    assert preview["scope"] == "role_activation_reputation_gate_preview_only"
    assert preview["payload_specific_requirements_included"] is False
    assert preview["roles"]["validator"]["eligible"] is True
    assert matrix["eligibility"]["validator_operator"]["eligible"] is False
    assert state == before
