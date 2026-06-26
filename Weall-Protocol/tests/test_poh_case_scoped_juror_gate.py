from weall.runtime.gate_expr import eval_gate


def _ledger() -> dict:
    return {
        "accounts": {
            "@alice": {"poh_tier": 2},
            "@live-juror-1": {"poh_tier": 2},
            "@live-juror-2": {"poh_tier": 2},
            "@tier2-juror-1": {"poh_tier": 2},
            "@unassigned": {"poh_tier": 2},
        },
        "params": {"allow_case_scoped_juror_without_role": True},
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
            "live_cases": {
                "poh3:@alice:5": {
                    "case_id": "poh3:@alice:5",
                    "account_id": "@alice",
                    "jurors": {
                        "@live-juror-1": {
                            "role": "interacting",
                            "accepted": None,
                            "attended": None,
                            "verdict": None,
                        },
                        "@live-juror-2": {
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


def test_live_case_assignment_satisfies_juror_gate() -> None:
    ok, meta = eval_gate(
        "Juror",
        signer="@live-juror-1",
        ledger=_ledger(),
        payload={"case_id": "poh3:@alice:5"},
        tx_type="POH_LIVE_JUROR_ACCEPT",
    )

    assert ok is True
    assert meta["expr"] == "Juror"


def test_tier2_case_assignment_satisfies_juror_gate() -> None:
    ok, _meta = eval_gate(
        "Juror",
        signer="@tier2-juror-1",
        ledger=_ledger(),
        payload={"case_id": "poh2:@alice:4"},
        tx_type="POH_TIER2_REVIEW_SUBMIT",
    )

    assert ok is True


def test_unassigned_poh_account_does_not_satisfy_juror_gate() -> None:
    ok, meta = eval_gate(
        "Juror",
        signer="@unassigned",
        ledger=_ledger(),
        payload={"case_id": "poh3:@alice:5"},
        tx_type="POH_LIVE_VERDICT_SUBMIT",
    )

    assert ok is False
    assert meta["expr"] == "Juror"


def test_replaced_poh_juror_does_not_satisfy_gate() -> None:
    ledger = _ledger()
    ledger["poh"]["live_cases"]["poh3:@alice:5"]["jurors"]["@live-juror-1"]["replaced"] = True

    ok, _meta = eval_gate(
        "Juror",
        signer="@live-juror-1",
        ledger=ledger,
        payload={"case_id": "poh3:@alice:5"},
        tx_type="POH_LIVE_VERDICT_SUBMIT",
    )

    assert ok is False
