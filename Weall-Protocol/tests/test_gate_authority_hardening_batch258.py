from __future__ import annotations

from weall.runtime.gate_expr import eval_gate


def test_validator_registry_membership_alone_does_not_satisfy_validator_gate_batch258() -> None:
    ledger = {
        "accounts": {"@stale-validator": {"poh_tier": 2}},
        "roles": {"validators": {"active_set": [], "by_id": {}}},
        "validators": {"registry": {"@stale-validator": {"status": "candidate"}}},
        "consensus": {"validators": {"registry": {"@stale-validator": {"status": "candidate"}}}},
    }

    ok, meta = eval_gate("Validator", signer="@stale-validator", ledger=ledger, payload={})

    assert ok is False
    assert meta["expr"] == "Validator"


def test_active_validator_set_satisfies_validator_gate_batch258() -> None:
    ledger = {
        "accounts": {"@validator": {"poh_tier": 2}},
        "roles": {"validators": {"active_set": ["@validator"], "by_id": {}}},
    }

    ok, _meta = eval_gate("Validator", signer="@validator", ledger=ledger, payload={})

    assert ok is True


def test_suspended_validator_record_overrides_active_set_batch258() -> None:
    ledger = {
        "accounts": {"@validator": {"poh_tier": 2}},
        "roles": {
            "validators": {
                "active_set": ["@validator"],
                "by_id": {"@validator": {"active": True, "suspended": True}},
            }
        },
    }

    ok, _meta = eval_gate("Validator", signer="@validator", ledger=ledger, payload={})

    assert ok is False


def test_validator_does_not_inherit_juror_authority_batch258() -> None:
    ledger = {
        "accounts": {"@validator": {"poh_tier": 2}},
        "roles": {"validators": {"active_set": ["@validator"], "by_id": {}}},
    }

    ok, _meta = eval_gate("Juror", signer="@validator", ledger=ledger, payload={})

    assert ok is False


def test_case_assignment_without_juror_role_denied_by_default_batch258() -> None:
    ledger = {
        "accounts": {"@assigned": {"poh_tier": 2}},
        "roles": {"jurors": {"active_set": [], "by_id": {}}},
        "poh": {
            "live_cases": {
                "live:@subject:1": {
                    "case_id": "live:@subject:1",
                    "jurors": {"@assigned": {"status": "assigned"}},
                }
            }
        },
    }

    ok, _meta = eval_gate(
        "Juror",
        signer="@assigned",
        ledger=ledger,
        payload={"case_id": "live:@subject:1"},
    )

    assert ok is False


def test_active_tier2_juror_must_still_be_assigned_for_case_scope_batch258() -> None:
    ledger = {
        "accounts": {"@juror": {"poh_tier": 2}},
        "roles": {"jurors": {"active_set": ["@juror"], "by_id": {}}},
        "poh": {
            "live_cases": {
                "live:@subject:1": {
                    "case_id": "live:@subject:1",
                    "jurors": {"@other": {"status": "assigned"}},
                }
            }
        },
    }

    ok, _meta = eval_gate(
        "Juror",
        signer="@juror",
        ledger=ledger,
        payload={"case_id": "live:@subject:1"},
    )

    assert ok is False


def test_active_tier2_assigned_juror_satisfies_case_scope_batch258() -> None:
    ledger = {
        "accounts": {"@juror": {"poh_tier": 2}},
        "roles": {"jurors": {"active_set": ["@juror"], "by_id": {}}},
        "poh": {
            "live_cases": {
                "live:@subject:1": {
                    "case_id": "live:@subject:1",
                    "jurors": {"@juror": {"status": "assigned"}},
                }
            }
        },
    }

    ok, _meta = eval_gate(
        "Juror",
        signer="@juror",
        ledger=ledger,
        payload={"case_id": "live:@subject:1"},
    )

    assert ok is True


def test_bootstrap_case_scoped_juror_without_role_requires_chain_param_batch258() -> None:
    ledger = {
        "accounts": {"@assigned": {"poh_tier": 2}},
        "params": {"allow_case_scoped_juror_without_role": True},
        "roles": {"jurors": {"active_set": [], "by_id": {}}},
        "poh": {
            "live_cases": {
                "live:@subject:1": {
                    "case_id": "live:@subject:1",
                    "jurors": {"@assigned": {"status": "assigned"}},
                }
            }
        },
    }

    ok, _meta = eval_gate(
        "Juror",
        signer="@assigned",
        ledger=ledger,
        payload={"case_id": "live:@subject:1"},
    )

    assert ok is True
