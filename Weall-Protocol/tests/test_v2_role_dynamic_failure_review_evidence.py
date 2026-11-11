"""Bounded evidence for dynamic V2 role-gate failures; not semantic approval.

The V2 AST extractor cannot infer RolesApplyError(code, reason) when both
arguments come from a chain-state-dependent predicate. These tests establish
its actual pure-predicate outcomes and typed exception propagation without
changing accepted review digests or activating any role authority.
"""

from __future__ import annotations

import pytest

from weall.runtime import reputation_role_gate as gate
from weall.runtime.apply import roles


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
