from weall.runtime.gate_expr import eval_gate


def _ledger() -> dict:
    return {
        "accounts": {
            "@alice": {"poh_tier": 2},
            "@tier3-juror-1": {"poh_tier": 3},
            "@tier3-juror-2": {"poh_tier": 3},
            "@tier2-juror-1": {"poh_tier": 3},
            "@unassigned": {"poh_tier": 3},
        },
        "poh": {
            "tier2_cases": {
                "poh2:@alice:4": {
                    "case_id": "poh2:@alice:4",
                    "account_id": "@alice",
                    "jurors": {
                        "@tier2-juror-1": {"status": "assigned", "verdict": None},
                    },
                }
            },
            "tier3_cases": {
                "poh3:@alice:5": {
                    "case_id": "poh3:@alice:5",
                    "account_id": "@alice",
                    "jurors": {
                        "@tier3-juror-1": {
                            "role": "interacting",
                            "accepted": None,
                            "attended": None,
                            "verdict": None,
                        },
                        "@tier3-juror-2": {
                            "role": "observing",
                            "accepted": True,
                            "attended": True,
                            "verdict": None,
                        },
                    },
                }
            },
        },
    }


def test_tier3_case_assignment_satisfies_juror_gate_batch233() -> None:
    ok, meta = eval_gate(
        "Juror",
        signer="@tier3-juror-1",
        ledger=_ledger(),
        payload={"case_id": "poh3:@alice:5"},
        tx_type="POH_TIER3_JUROR_ACCEPT",
    )

    assert ok is True
    assert meta["expr"] == "Juror"


def test_tier2_case_assignment_satisfies_juror_gate_batch233() -> None:
    ok, _meta = eval_gate(
        "Juror",
        signer="@tier2-juror-1",
        ledger=_ledger(),
        payload={"case_id": "poh2:@alice:4"},
        tx_type="POH_TIER2_REVIEW_SUBMIT",
    )

    assert ok is True


def test_unassigned_poh_account_does_not_satisfy_juror_gate_batch233() -> None:
    ok, meta = eval_gate(
        "Juror",
        signer="@unassigned",
        ledger=_ledger(),
        payload={"case_id": "poh3:@alice:5"},
        tx_type="POH_TIER3_VERDICT_SUBMIT",
    )

    assert ok is False
    assert meta["expr"] == "Juror"


def test_replaced_poh_juror_does_not_satisfy_gate_batch233() -> None:
    ledger = _ledger()
    ledger["poh"]["tier3_cases"]["poh3:@alice:5"]["jurors"]["@tier3-juror-1"]["replaced"] = True

    ok, _meta = eval_gate(
        "Juror",
        signer="@tier3-juror-1",
        ledger=ledger,
        payload={"case_id": "poh3:@alice:5"},
        tx_type="POH_TIER3_VERDICT_SUBMIT",
    )

    assert ok is False
