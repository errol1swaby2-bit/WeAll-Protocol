"""Bounded evidence for dynamic V2 role-gate failures; not semantic approval.

The V2 AST extractor cannot infer RolesApplyError(code, reason) when both
arguments come from a chain-state-dependent predicate. These tests establish
its actual pure-predicate outcomes and typed exception propagation without
changing accepted review digests or activating any role authority.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime import reputation_role_gate as gate
from weall.runtime.apply import roles
from weall.runtime.tx_admission_types import TxEnvelope


@pytest.mark.parametrize(
    ("case", "expected_code", "expected_reason"),
    [
        ("missing_account", "not_found", "account_not_found"),
        ("banned", "forbidden", "account_restricted"),
        ("locked", "forbidden", "account_restricted"),
        ("poh_insufficient", "forbidden", "live_verification_required"),
        ("revoked", "forbidden", "role_eligibility_revoked"),
        ("reputation_insufficient", "forbidden", "reputation_insufficient"),
        ("unsupported_policy", "forbidden", "policy_unknown"),
        ("legacy_eligible", "ok", "eligible"),
        ("v2_canonical_denied", "forbidden", "canonical_role_reputation_ineligible"),
        ("v2_unmapped_role", "ok", "eligible"),
    ],
)
def test_dynamic_role_gate_failure_matrix_is_not_exception_class_name(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_code: str,
    expected_reason: str,
) -> None:
    state = {
        "accounts": {"@candidate": {"banned": False, "locked": False}},
        "params": {},
        "reputation": {"role_eligibility": {"@candidate": {"roles": {}}}},
    }
    acct = "@candidate"
    role = "juror"
    if case == "missing_account":
        state["accounts"] = {}
    elif case in {"banned", "locked"}:
        state["accounts"][acct][case] = True
    elif case == "revoked":
        state["reputation"]["role_eligibility"][acct]["roles"]["juror"] = False
    elif case == "unsupported_policy":
        state["params"]["reputation_role_gate_version"] = 3
    elif case in {"v2_canonical_denied", "v2_unmapped_role"}:
        state["params"]["reputation_role_gate_version"] = 2
    if case == "v2_unmapped_role":
        role = "emissary"

    monkeypatch.setattr(
        gate,
        "effective_poh_tier",
        lambda _state, _account: 1 if case == "poh_insufficient" else 3,
    )
    monkeypatch.setattr(
        gate,
        "account_reputation_units",
        lambda _account, default=0: 0 if case == "reputation_insufficient" else 1000,
    )
    monkeypatch.setattr(
        gate,
        "derive_role_eligibility",
        lambda _state, _account: {
            "juror_assignment": {"eligible": False, "reasons": ["test_only_canonical_reason"]}
        },
    )

    result = gate.role_activation_reputation_decision(
        state, acct, role=role, minimum_reputation_milli=500
    )
    assert result["code"] == expected_code
    assert result["reason"] == expected_reason
    assert result["other_role_specific_checks_required"] is True
    assert result["code"] != "RolesApplyError"
    if case == "legacy_eligible":
        assert result["gate_version"] == 1
        assert result["canonical_enforcement"] is False
    if case == "v2_canonical_denied":
        assert result["gate_version"] == 2
        assert result["canonical_enforcement"] is True
        assert result["canonical_reasons"] == ["test_only_canonical_reason"]
    if case == "v2_unmapped_role":
        assert result["canonical_enforcement"] is False
        assert result["canonical_role"] is None


def test_role_applier_propagates_dynamic_typed_failure_and_v2_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def rejected(_ledger: dict, _account: str, **_kwargs: object) -> dict:
        return {
            "eligible": False,
            "code": "forbidden",
            "reason": "canonical_role_reputation_ineligible",
            "gate_version": 2,
            "canonical_role": "juror_assignment",
            "canonical_reasons": ["test_only_canonical_reason"],
        }

    monkeypatch.setattr(roles, "role_activation_reputation_decision", rejected)
    with pytest.raises(roles.RolesApplyError) as failure:
        roles._require_role_activation_eligible(
            {"accounts": {"@candidate": {}}},
            "@candidate",
            role="juror",
            minimum_reputation_milli=500,
        )
    assert failure.value.code == "forbidden"
    assert failure.value.reason == "canonical_role_reputation_ineligible"
    assert failure.value.details == {
        "account_id": "@candidate",
        "role": "juror",
        "gate_version": 2,
        "canonical_role": "juror_assignment",
        "canonical_reasons": ["test_only_canonical_reason"],
    }



def _reviewer_withdrawal_state(*, gate_version: int = 1, enrolled: bool = True) -> dict:
    """A seeded role record only; no constitutional election or PoH proof."""
    return {
        "height": 12,
        "params": {"reputation_role_gate_version": gate_version},
        "accounts": {
            "@candidate": {
                "poh_tier": 1,
                "banned": True,
                "locked": False,
                "reputation_milli": 0,
            }
        },
        "roles": {
            "jurors": {
                "by_id": {
                    "@candidate": {
                        "account_id": "@candidate",
                        "enrolled": enrolled,
                        "active": True,
                        "status": "active",
                        "responsibilities": {
                            "reviewer": {
                                "content_review": {
                                    "opted_in": True,
                                    "active": True,
                                    "updated_at_nonce": 7,
                                },
                                "dispute_review": {
                                    "opted_in": True,
                                    "active": True,
                                    "updated_at_nonce": 7,
                                },
                            }
                        },
                    }
                },
                "active_set": ["@candidate"],
            }
        },
    }


def _reviewer_env(tx_type: str, *, signer: str = "@candidate") -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=8,
        payload={"account_id": "@candidate", "lane": "content_review"},
    )


@pytest.mark.parametrize("gate_version", [1, 2, 3])
def test_reviewer_lane_opt_out_does_not_recheck_role_activation_gate(
    monkeypatch: pytest.MonkeyPatch, gate_version: int
) -> None:
    """A denied role activation must not trap a previously enrolled reviewer in a lane."""
    state = _reviewer_withdrawal_state(gate_version=gate_version)
    before_accounts = deepcopy(state["accounts"])
    before_params = deepcopy(state["params"])
    other_lane = deepcopy(
        state["roles"]["jurors"]["by_id"]["@candidate"]["responsibilities"]["reviewer"][
            "dispute_review"
        ]
    )

    def must_not_call_gate(*_args: object, **_kwargs: object) -> dict:
        raise AssertionError("opt_out_must_not_invoke_role_activation_gate")

    monkeypatch.setattr(roles, "role_activation_reputation_decision", must_not_call_gate)
    result = roles.apply_roles(state, _reviewer_env("REVIEWER_LANE_OPT_OUT"))
    assert result == {
        "applied": "REVIEWER_LANE_OPT_OUT",
        "account_id": "@candidate",
        "lanes": ["content_review"],
        "reassigned_content_reviews": 0,
    }
    jurors = state["roles"]["jurors"]
    candidate = jurors["by_id"]["@candidate"]
    reviewer = candidate["responsibilities"]["reviewer"]
    assert reviewer["content_review"]["opted_in"] is False
    assert reviewer["content_review"]["active"] is False
    assert reviewer["content_review"]["withdrawn_at_nonce"] == 8
    assert reviewer["dispute_review"] == other_lane
    assert candidate["active"] is True
    assert candidate["status"] == "active"
    assert jurors["active_set"] == ["@candidate"]
    assert state["accounts"] == before_accounts
    assert state["params"] == before_params


@pytest.mark.parametrize("gate_version", [1, 2])
def test_reviewer_lane_opt_in_still_enforces_dynamic_gate_fail_closed(
    monkeypatch: pytest.MonkeyPatch, gate_version: int
) -> None:
    """Same shared handler, opposite branch: opt-in cannot bypass eligibility."""
    state = _reviewer_withdrawal_state(gate_version=gate_version)
    before = deepcopy(state)
    seen: list[tuple[str, int]] = []

    def reject(_state: dict, _account: str, *, role: str, minimum_reputation_milli: int) -> dict:
        seen.append((role, minimum_reputation_milli))
        return {
            "eligible": False,
            "code": "forbidden",
            "reason": "account_restricted",
        }

    monkeypatch.setattr(roles, "role_activation_reputation_decision", reject)
    with pytest.raises(roles.RolesApplyError) as raised:
        roles.apply_roles(state, _reviewer_env("REVIEWER_LANE_OPT_IN"))
    assert (raised.value.code, raised.value.reason) == ("forbidden", "account_restricted")
    assert seen == [("juror", 0)]
    assert state == before


def test_reviewer_lane_opt_out_not_enrolled_remains_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _reviewer_withdrawal_state(enrolled=False)
    before = deepcopy(state)

    def must_not_call_gate(*_args: object, **_kwargs: object) -> dict:
        raise AssertionError("not_enrolled_opt_out_must_not_invoke_activation_gate")

    monkeypatch.setattr(roles, "role_activation_reputation_decision", must_not_call_gate)
    with pytest.raises(roles.RolesApplyError) as raised:
        roles.apply_roles(state, _reviewer_env("REVIEWER_LANE_OPT_OUT"))
    assert (raised.value.code, raised.value.reason) == ("not_found", "juror_not_enrolled")
    assert state == before


def test_reviewer_lane_opt_out_cannot_change_another_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _reviewer_withdrawal_state()
    before = deepcopy(state)

    def must_not_call_gate(*_args: object, **_kwargs: object) -> dict:
        raise AssertionError("unauthorized_opt_out_must_not_invoke_activation_gate")

    monkeypatch.setattr(roles, "role_activation_reputation_decision", must_not_call_gate)
    with pytest.raises(roles.RolesApplyError) as raised:
        roles.apply_roles(state, _reviewer_env("REVIEWER_LANE_OPT_OUT", signer="@other"))
    assert (raised.value.code, raised.value.reason) == (
        "forbidden",
        "only_account_can_update_reviewer_lane",
    )
    assert state == before


def test_juror_reinstate_alias_still_checks_role_activation_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The alias invokes _apply_role_juror_activate and its versioned gate."""
    state = _reviewer_withdrawal_state(gate_version=2)
    candidate = state["roles"]["jurors"]["by_id"]["@candidate"]
    candidate["active"] = False
    candidate["status"] = "paused"
    state["roles"]["jurors"]["active_set"] = []
    before = deepcopy(state)
    calls: list[str] = []

    def reject(_state: dict, _account: str, *, role: str, minimum_reputation_milli: int) -> dict:
        calls.append(role)
        return {
            "eligible": False,
            "code": "forbidden",
            "reason": "account_restricted",
        }

    monkeypatch.setattr(roles, "role_activation_reputation_decision", reject)
    with pytest.raises(roles.RolesApplyError) as raised:
        roles.apply_roles(
            state,
            TxEnvelope(
                tx_type="ROLE_JUROR_REINSTATE",
                signer="@candidate",
                nonce=8,
                payload={"account_id": "@candidate"},
            ),
        )
    assert (raised.value.code, raised.value.reason) == ("forbidden", "account_restricted")
    assert calls == ["juror"]
    assert state == before
