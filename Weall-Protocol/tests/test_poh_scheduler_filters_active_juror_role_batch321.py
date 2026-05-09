from __future__ import annotations

import pytest

from weall.runtime.gate_expr import eval_gate
from weall.runtime.poh.juror_select import eligible_live_jurors, pick_async_jurors, pick_tier2_jurors


def _state(*, bootstrap_compat: bool = False) -> dict:
    params = {}
    if bootstrap_compat:
        params["allow_case_scoped_juror_without_role"] = True
    return {
        "height": 7,
        "tip": "tip-a",
        "params": params,
        "accounts": {
            "@target": {"poh_tier": 0, "nonce": 0, "reputation_milli": 0},
            "@active": {"poh_tier": 2, "nonce": 0, "reputation_milli": 1000},
            "@tier2_no_role": {"poh_tier": 2, "nonce": 0, "reputation_milli": 1000},
            "@revoked": {"poh_tier": 2, "nonce": 0, "reputation_milli": 1000},
            "@tier1": {"poh_tier": 1, "nonce": 0, "reputation_milli": 1000},
        },
        "roles": {
            "jurors": {
                "active_set": ["@active", "@revoked"],
                "by_id": {
                    "@active": {"active": True},
                    "@revoked": {"active": True, "revoked": True},
                },
            }
        },
        "poh": {
            "async_cases": {
                "case-1": {
                    "case_id": "case-1",
                    "account_id": "@target",
                    "jurors": {"@active": {"status": "assigned"}},
                }
            }
        },
    }


def test_poh_assignment_pool_requires_active_juror_role_by_default_batch321() -> None:
    state = _state()

    assert eligible_live_jurors(state=state) == ["@active"]
    assert pick_async_jurors(state=state, case_id="case-1", target_account="@target", n_jurors=1) == ["@active"]
    assert pick_tier2_jurors(state=state, case_id="case-2", target_account="@target", n_jurors=1) == ["@active"]

    with pytest.raises(ValueError, match="insufficient_eligible_jurors"):
        pick_async_jurors(state=state, case_id="case-1", target_account="@target", n_jurors=2)


def test_poh_assignment_pool_matches_juror_admission_gate_batch321() -> None:
    state = _state()

    ok, _meta = eval_gate(
        "Juror",
        signer="@active",
        state=state,
        payload={"case_id": "case-1"},
        tx_type="POH_ASYNC_REVIEW_SUBMIT",
    )
    assert ok is True

    ok, _meta = eval_gate(
        "Juror",
        signer="@tier2_no_role",
        state=state,
        payload={"case_id": "case-1"},
        tx_type="POH_ASYNC_REVIEW_SUBMIT",
    )
    assert ok is False

    assert "@tier2_no_role" not in eligible_live_jurors(state=state)


def test_poh_bootstrap_compat_flag_is_explicit_and_chain_state_bound_batch321() -> None:
    state = _state(bootstrap_compat=True)

    # Controlled bootstrap/devnet compatibility can still assign Tier2 accounts
    # before the active Juror role set is complete, but only because chain state
    # explicitly opts into the same case-scoped fallback used by the gate.
    assert eligible_live_jurors(state=state) == ["@active", "@tier2_no_role"]
