"""Independent T0 reference model of OBSERVED group STV behavior.

Not a normative STV implementation. In particular, production code reassigns
both retained weight AND surplus after electing a candidate. Because the split
parcels retain the same preferences and their weights sum to the original
weight exactly, its effective active-preference transfers are full-weight.
This reference intentionally uses no production tally code, Fraction, piles,
or production ballot classes to expose that equivalence and detect drift.
No signatures, cryptography or consensus authority here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "specs/research/group_emissary_stv_t0_vectors_v0_1.json"


def observed_stv_reference(
    *, candidates: list[str], ballots: list[dict[str, Any]], seats: int
) -> dict[str, Any]:
    """Count one unit per complete active preference; current *observed* behavior."""
    choices = sorted({name for name in candidates if isinstance(name, str) and name.strip()})
    if not choices or seats <= 0:
        return {"quota": None, "raw_winners": [], "trace": []}

    clean_ballots: list[list[str]] = []
    for ballot in ballots:
        ranking = ballot.get("ranking")
        if not isinstance(ranking, list):
            continue
        seen: set[str] = set()
        accepted: list[str] = []
        for preference in ranking:
            if not isinstance(preference, str):
                continue
            text = preference.strip()
            if text in choices and text not in seen:
                seen.add(text)
                accepted.append(text)
        if accepted:
            clean_ballots.append(accepted)

    quota = len(clean_ballots) // (seats + 1) + 1
    remaining = set(choices)
    winners: list[str] = []
    events: list[dict[str, Any]] = []

    while remaining and len(winners) < seats:
        vacancies = seats - len(winners)
        if len(remaining) <= vacancies:
            fill = sorted(remaining)
            winners.extend(fill)
            events.append({"action": "fill", "ids": fill})
            break

        counts = {candidate: 0 for candidate in remaining}
        for ballot in clean_ballots:
            preferred = next((name for name in ballot if name in remaining), None)
            if preferred is not None:
                counts[preferred] += 1

        eligible = sorted(
            (name for name in remaining if counts[name] >= quota),
            key=lambda name: (-counts[name], name),
        )
        if eligible:
            winner = eligible[0]
            winners.append(winner)
            events.append({"action": "elect", "id": winner, "tally": counts[winner]})
            remaining.remove(winner)
            continue

        loser = min(remaining, key=lambda name: (counts[name], name))
        events.append({"action": "eliminate", "id": loser, "tally": counts[loser]})
        remaining.remove(loser)

    return {"quota": quota, "raw_winners": winners, "trace": events}


def validate_corpus(value: Any) -> list[str]:
    """Exact stable golden vector checks and metadata fail-close, no approval."""
    failures: list[str] = []
    if not isinstance(value, dict):
        return ["corpus_is_not_object"]
    for key, expected in (
        ("schema_version", "weall.group-emissary-stv.t0.v0.1"),
        ("status", "OBSERVED_CURRENT_BEHAVIOR_NOT_APPROVAL"),
        ("normative_stv_compliance_claimed", False),
        ("confidential_ballot_claimed", False),
        ("consensus_changes_authorized", False),
        ("reference_model", "full_active_preference_transfer_observed_not_normative_droop"),
    ):
        if value.get(key) != expected:
            failures.append(f"invalid_{key}")

    cases = value.get("cases")
    required = value.get("required_vectors")
    if not isinstance(cases, list) or not isinstance(required, list):
        return failures + ["missing_cases_or_required_vectors"]
    actual = [case.get("id") for case in cases if isinstance(case, dict)]
    if len(actual) != len(cases) or len(actual) != len(set(actual)):
        failures.append("duplicate_or_bad_case_id")
    if set(actual) != set(required) or len(actual) != len(required) or len(cases) < 9:
        failures.append("missing_or_extra_required_vectors")

    for item in cases:
        if not isinstance(item, dict):
            failures.append("invalid_case")
            continue
        name = str(item.get("id", ""))
        allowed = {"raw_helper_only", "finalization_integration"}
        if item.get("scope") not in allowed:
            failures.append(f"bad_scope_{name}")
            continue
        if not isinstance(item.get("seats"), int) or isinstance(item.get("seats"), bool):
            failures.append(f"invalid_seats_{name}")
            continue
        if not isinstance(item.get("candidates"), list) or not isinstance(
            item.get("ballots"), list
        ):
            failures.append(f"invalid_input_{name}")
            continue
        if any(not isinstance(ballot, dict) for ballot in item["ballots"]):
            failures.append(f"invalid_ballot_{name}")
            continue
        if item["scope"] == "finalization_integration" and (
            item["seats"] < 5 or len(set(item["candidates"])) < 5
        ):
            failures.append(f"invalid_finalization_fixture_{name}")
        actual_result = observed_stv_reference(
            candidates=item["candidates"], ballots=item["ballots"], seats=item["seats"]
        )
        expected = item.get("expected")
        if not isinstance(expected, dict):
            failures.append(f"missing_expected_{name}")
            continue
        for key in ("quota", "raw_winners", "trace"):
            if expected.get(key) != actual_result[key]:
                failures.append(f"mismatched_{key}_{name}")
        status = expected.get("final_status")
        expected_winners = expected.get("final_winners")
        if item["scope"] == "raw_helper_only":
            if status != "not_applicable" or expected_winners is not None:
                failures.append(f"raw_helper_cannot_claim_finality_{name}")
        elif status == "no_decision":
            if item["ballots"] or expected_winners != []:
                failures.append(f"false_no_decision_{name}")
        elif status == "finalized":
            if not item["ballots"] or expected_winners != actual_result["raw_winners"]:
                failures.append(f"false_finalized_result_{name}")
        else:
            failures.append(f"missing_finalization_status_{name}")
        if not isinstance(item.get("risk_note"), str) or not item["risk_note"]:
            failures.append(f"missing_risk_note_{name}")
    return failures


def main() -> int:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    failures = validate_corpus(corpus)
    if failures:
        for failure in sorted(set(failures)):
            print(f"FAIL: {failure}")
        return 1
    print("PASS: observed STV golden vectors; NOT normative STV or confidential-ballot proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
