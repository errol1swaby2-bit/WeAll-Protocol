"""SYSTEM GOV_TALLY_PUBLISH payload must exactly model emitted canonical counts.

This validates payload shapes only. Eligibility, producer authorization, lineage,
queue binding and constitutional governance are separate requirements.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from weall.runtime.tx_schema import GovTallyPublishPayload, validate_tx_envelope


def _binary_tally() -> dict:
    return {
        "proposal_id": "real-signed-governance-fixture",
        "vote_window": "final",
        "vote_model": "binary_yes_no_abstain",
        "eligible_validator_count": 2,
        "required_votes": 2,
        "total_votes": 2,
        "quorum_met": True,
        "yes": 2,
        "no": 0,
        "abstain": 0,
        "passed": True,
    }


def test_signed_binary_ballot_system_tally_passes_strict_schema() -> None:
    envelope, body = validate_tx_envelope(
        {
            "tx_type": "GOV_TALLY_PUBLISH",
            "signer": "SYSTEM",
            "nonce": 0,
            "system": True,
            "payload": _binary_tally(),
        }
    )
    assert envelope.system is True
    assert isinstance(body, GovTallyPublishPayload)
    assert body.vote_window == "final"
    assert body.vote_model == "binary_yes_no_abstain"
    assert body.required_votes == 2
    assert body.yes == 2


@pytest.mark.parametrize("selected", ["first-choice", ""])
def test_option_vote_tallies_include_all_deterministic_public_fields(selected: str) -> None:
    payload = {
        **_binary_tally(),
        "vote_model": "multi_option_plurality",
        "option_tallies": {"first-choice": 2, "second-choice": 0},
        "invalid_option_votes": 0,
        "selected_option_id": selected,
        "tie": selected == "",
        "tie_option_ids": ["first-choice", "second-choice"] if selected == "" else [],
        "outcome": "tie" if selected == "" else "selected",
        "deterministic_tie_break": "no automatic winner; tied option_ids are published in lexicographic order",
    }
    body = GovTallyPublishPayload.model_validate(payload)
    assert body.option_tallies == payload["option_tallies"]
    assert body.selected_option_id == selected
    assert body.tie == (selected == "")


def test_tally_schema_keeps_unknown_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        GovTallyPublishPayload.model_validate(
            {**_binary_tally(), "unauthorized_quorum_override": True}
        )
    with pytest.raises(ValidationError):
        GovTallyPublishPayload.model_validate({**_binary_tally(), "yes": -1})
