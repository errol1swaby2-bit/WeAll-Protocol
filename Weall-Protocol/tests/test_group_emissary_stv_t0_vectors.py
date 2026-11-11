"""T0 golden vectors for observed STV behavior, not normative STV certification.

This file compares the production helper with hard-coded golden outcomes and
an independent, no-Fraction full-preference reference in the research script.
It also checks finalization authority boundaries for single/zero ballots.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from runpy import run_path

import pytest

from weall.runtime.apply.groups import _stv_winners, apply_groups
from weall.runtime.tx_admission_types import TxEnvelope

T0 = run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/validate_group_emissary_stv_t0.py")
)
CORPUS = T0["CORPUS"]
observed_stv_reference = T0["observed_stv_reference"]
validate_corpus = T0["validate_corpus"]
VECTORS = json.loads(CORPUS.read_text(encoding="utf-8"))


def _production_winners(case: dict) -> list[str]:
    return _stv_winners(
        ballots_by_voter={ballot["voter"]: ballot["ranking"] for ballot in case["ballots"]},
        candidates=case["candidates"],
        seats=case["seats"],
    )


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda row: row["id"])
def test_golden_current_runtime_and_independent_reference(case: dict) -> None:
    expected = case["expected"]
    independently = observed_stv_reference(
        candidates=case["candidates"], ballots=case["ballots"], seats=case["seats"]
    )
    assert independently == {
        "quota": expected["quota"],
        "raw_winners": expected["raw_winners"],
        "trace": expected["trace"],
    }
    assert _production_winners(case) == expected["raw_winners"]
    reversed_case = {
        **case,
        "candidates": list(reversed(case["candidates"])),
        "ballots": list(reversed(case["ballots"])),
    }
    assert _production_winners(reversed_case) == expected["raw_winners"]


def test_t0_golden_manifest_no_normative_or_privacy_claims() -> None:
    assert validate_corpus(VECTORS) == []
    assert VECTORS["normative_stv_compliance_claimed"] is False
    assert VECTORS["confidential_ballot_claimed"] is False
    assert VECTORS["consensus_changes_authorized"] is False
    mutated = deepcopy(VECTORS)
    mutated["normative_stv_compliance_claimed"] = True
    assert validate_corpus(mutated)
    mutated = deepcopy(VECTORS)
    mutated["cases"][0]["expected"]["raw_winners"] = ["@fake"]
    assert validate_corpus(mutated)


def test_intended_first_seat_redistributes_full_preference_weight() -> None:
    case = next(row for row in VECTORS["cases"] if row["id"] == "first_seat_full_preference_redistribution")
    assert _production_winners(case) == ["@a", "@c"]
    assert case["expected"]["quota"] == 3
    # WeAll deliberately moves all four A-first votes to their next eligible
    # ranked choice C after A fills the first seat. Do not 'fix' this into
    # conventional quota-retaining STV without an explicit design change.
    assert case["expected"]["trace"][1] == {"action": "elect", "id": "@c", "tally": 4}


def test_five_seats_move_all_votes_to_next_ranked_candidate() -> None:
    case = next(
        row
        for row in VECTORS["cases"]
        if row["id"] == "five_seats_repeated_full_preference_redistribution"
    )
    assert case["expected"]["quota"] == 2
    assert _production_winners(case) == ["@a", "@b", "@c", "@d", "@e"]
    # All six voters support A, then B, then C, D and E. Each time a seat
    # is filled, full ballot weight follows the next still-eligible preference.
    assert case["expected"]["trace"] == [
        {"action": "elect", "id": candidate, "tally": 6}
        for candidate in ("@a", "@b", "@c", "@d", "@e")
    ]


def _tx(tx_type: str, signer: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="")


@pytest.mark.parametrize(
    "case_id",
    [
        "no_ballots_no_decision",
        "minimum_five_fill",
        "candidate_count_equals_seats",
        "five_seats_repeated_full_preference_redistribution",
    ]
)
def test_canonical_finalize_t0_golden_and_authority_boundary(case_id: str) -> None:
    case = next(row for row in VECTORS["cases"] if row["id"] == case_id)
    group_id = f"g:t0-{case_id}"
    election_id = f"e:t0-{case_id}"
    state: dict = {"height": 100}
    apply_groups(state, _tx("GROUP_CREATE", "@a", 1, {"group_id": group_id, "charter": "t0"}))
    group = state["roles"]["groups_by_id"][group_id]
    group["members"] = {
        account: {"joined_at_nonce": 1}
        for account in set(case["candidates"]) | {entry["voter"] for entry in case["ballots"]}
    }
    apply_groups(
        state,
        _tx(
            "GROUP_EMISSARY_ELECTION_CREATE",
            "@a",
            2,
            {
                "group_id": group_id,
                "election_id": election_id,
                "seats": case["seats"],
                "candidates": case["candidates"],
                "start_height": 101,
                "end_height": 103,
            },
        ),
    )
    original_group = deepcopy(group)
    treasury_id = group["treasury_id"]
    original_treasury = deepcopy(state["roles"]["treasuries_by_id"][treasury_id])
    for index, ballot in enumerate(case["ballots"], start=10):
        applied = apply_groups(
            state,
            _tx(
                "GROUP_EMISSARY_BALLOT_CAST",
                ballot["voter"],
                index,
                {"election_id": election_id, "ranking": ballot["ranking"]},
            ),
        )
        assert applied["applied"] == "GROUP_EMISSARY_BALLOT_CAST"
    state["height"] = 102
    result = apply_groups(
        state,
        _tx(
            "GROUP_EMISSARY_ELECTION_FINALIZE",
            "@a",
            99,
            {"group_id": group_id, "election_id": election_id},
        ),
    )
    stored = state["group_emissary_elections"][election_id]
    assert stored["status"] == case["expected"]["final_status"]
    assert stored["winners"] == case["expected"]["final_winners"]
    assert result["applied"] == "GROUP_EMISSARY_ELECTION_FINALIZE"
    if case["expected"]["final_status"] == "no_decision":
        assert result["status"] == "no_decision"
        assert group == original_group
        assert state["roles"]["treasuries_by_id"][treasury_id] == original_treasury
        repeated = apply_groups(
            state,
            _tx(
                "GROUP_EMISSARY_ELECTION_FINALIZE",
                "@a",
                100,
                {"group_id": group_id, "election_id": election_id},
            ),
        )
        assert repeated["status"] == "no_decision"
        assert repeated["deduped"] is True
    else:
        assert group["emissaries"] == case["expected"]["final_winners"]
        assert group["signers"] == case["expected"]["final_winners"]
        assert (
            state["roles"]["treasuries_by_id"][treasury_id]["signers"]
            == case["expected"]["final_winners"]
        )
