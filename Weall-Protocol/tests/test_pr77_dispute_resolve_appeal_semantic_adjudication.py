"""PR77: source-bound RESOLVE/APPEAL semantics, not severe sanction authorization.

These are synthetic direct-applier checks. They cannot authenticate real
system-queue origin, juror ballots, old-version historical replay or signoff.
"""

from __future__ import annotations

import copy

import pytest

from scripts.pr77_v2_semantic_review_packet import build_packet
from weall.runtime.apply import dispute
from weall.runtime.tx_admission import TxEnvelope


def _severe_state(*, clock: bool = True, experimental: bool = False) -> dict:
    panel = [f"juror-{n:02d}" for n in range(25)]
    substitutes = [f"sub-{n:02d}" for n in range(5)]
    voters = panel[:20]
    nullifiers = {
        dispute._dispute_ballot_nullifier(
            dispute_id="severe-case", panel_round=1, juror=juror, appeal=False
        ): {"final": True, "panel_round": 1, "height": 11}
        for juror in voters
    }
    return {
        "height": 11,
        "meta": {"constitutional_clock": {"enabled": clock}},
        "params": {
            "m3_civic_governance_strict": True,
            "experimental_severe_auto_appeal_v0": experimental,
        },
        "accounts": {"@target": {"poh_tier": 2, "banned": False, "locked": False}},
        "roles": {"jurors": {"active_set": panel + substitutes}},
        "disputes_by_id": {
            "severe-case": {
                "id": "severe-case",
                "target_type": "account",
                "target_id": "@target",
                "target_owner": "@target",
                "appeal_allowed_accounts": ["@target"],
                "sanction_class": "S4",
                "stage": "juror_review",
                "resolved": False,
                "panel_status": "assigned",
                "panel_round": 1,
                "panel_commitment": "synthetic-unverified",
                "assigned_jurors": panel,
                "substitute_juror_ids": substitutes,
                "eligible_juror_ids": panel,
                "required_votes": 17,
                "vote_counts": {"yes": 20},
                "voted_juror_ids": voters,
                "ballot_nullifiers": nullifiers,
                "votes": {},
                "jurors": {},
            }
        },
        "system_queue": [],
    }


def _resolve(*, resolution_outcome: str = "report_upheld") -> TxEnvelope:
    return TxEnvelope(
        tx_type="DISPUTE_RESOLVE",
        signer="SYSTEM",
        nonce=12,
        system=True,
        sig="synthetic-not-authenticated",
        payload={
            "dispute_id": "severe-case",
            "resolution": {"outcome": resolution_outcome},
            "_system_queue_id": "synthetic-unverified-parent",
        },
    )


def _appeal() -> TxEnvelope:
    return TxEnvelope(
        tx_type="DISPUTE_APPEAL",
        signer="@target",
        nonce=13,
        system=False,
        sig="synthetic-not-authenticated",
        payload={"dispute_id": "severe-case"},
    )


def _require_denied_without_mutation(state: dict, tx: TxEnvelope, reason: str) -> None:
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as raised:
        dispute.apply_dispute(state, tx)
    assert raised.value.reason == reason
    assert state == before
    assert state["system_queue"] == before["system_queue"]


@pytest.mark.parametrize(
    ("tx_type", "expected_added"),
    [
        (
            "DISPUTE_RESOLVE",
            {
                ("conflict", "automatic_severe_appeal_already_assigned"),
                ("forbidden", "severe_sanction_initial_outcome_mismatch"),
                ("forbidden", "severe_sanction_initial_twenty_votes_unverified"),
            },
        ),
        (
            "DISPUTE_APPEAL",
            {("conflict", "automatic_severe_appeal_already_assigned")},
        ),
    ],
)
def test_v2_review_material_binds_exact_resolve_appeal_deltas(
    tx_type: str, expected_added: set[tuple[str, str]]
) -> None:
    packet = build_packet()
    row = next(row for row in packet["transactions"] if row["tx_type"] == tx_type)
    assert row["archive_matches_accepted_digest"] is True
    assert row["current_material_digest"] != row["accepted_review_digest"]
    assert row["archived_implementation_source"] == row["current_implementation_source"]
    # Durable pending appeal records add canonical writes. This is a material
    # source delta, not an accepted semantic-review or human signoff.
    expected_fields = ["failure_codes", "state_reads"]
    if tx_type == "DISPUTE_APPEAL":
        expected_fields.append("state_writes")
    assert row["changed_field_names"] == expected_fields
    assert {
        (entry["code"], entry["reason"]) for entry in row["failure_code_deltas"]["added"]
    } == expected_added
    # The former insufficient-panel *rejection* was intentionally removed.
    # Its replacement is durable appeal_pending_panel, not release authority.
    expected_removed = (
        [{"code": "forbidden", "reason": "insufficient_fresh_appeal_panel"}]
        if tx_type == "DISPUTE_APPEAL"
        else []
    )
    assert row["failure_code_deltas"]["removed"] == expected_removed
    state_read_diff = next(
        change for change in row["changed_fields"] if change["field"] == "state_reads"
    )
    assert state_read_diff["previous"] != state_read_diff["current"]
    assert row["signed_off_for_current_digest"] is False
    assert row["historical_replay_proven"] is False
    assert packet["independent_human_approval_recorded_by_this_packet"] is False


def test_initial_vote_metadata_cannot_bypass_twenty_required_votes() -> None:
    state = _severe_state()
    case = state["disputes_by_id"]["severe-case"]
    case["vote_counts"]["yes"] = 19
    case["voted_juror_ids"] = case["voted_juror_ids"][:19]
    _require_denied_without_mutation(
        state,
        _resolve(),
        "severe_sanction_initial_twenty_votes_unverified",
    )


@pytest.mark.parametrize("outcome", ["report_not_upheld", "undecided", ""])
def test_resolve_rejects_system_supplied_outcome_conflicting_with_ballots(outcome: str) -> None:
    state = _severe_state()
    _require_denied_without_mutation(
        state,
        _resolve(resolution_outcome=outcome),
        "severe_sanction_initial_outcome_mismatch",
    )


@pytest.mark.parametrize("experimental", [False, True])
def test_resolve_duplicate_auto_panel_conflict_requires_experimental_opt_in(
    experimental: bool,
) -> None:
    state = _severe_state(experimental=experimental)
    state["disputes_by_id"]["severe-case"]["automatic_appeal_record"] = {
        "source": "synthetic-non-authoritative"
    }
    if experimental:
        _require_denied_without_mutation(
            state,
            _resolve(),
            "automatic_severe_appeal_already_assigned",
        )
    else:
        # The default-off path must not treat a synthetic auto-panel marker
        # as evidence authorizing enforcement. It remains appealable.
        result = dispute.apply_dispute(state, _resolve())
        assert result["applied"] == "DISPUTE_RESOLVE"
        assert state["disputes_by_id"]["severe-case"]["stage"] == "appeal_window"
        assert state["system_queue"] == []


@pytest.mark.parametrize("experimental", [False, True])
def test_appeal_cannot_replace_recorded_auto_panel_even_if_experiment_disabled(
    experimental: bool,
) -> None:
    state = _severe_state(experimental=experimental)
    case = state["disputes_by_id"]["severe-case"]
    case["stage"] = "appeal_window"
    case["resolved"] = True
    case["automatic_appeal_record"] = {"source": "synthetic-non-authoritative"}
    _require_denied_without_mutation(
        state,
        _appeal(),
        "automatic_severe_appeal_already_assigned",
    )


def test_resolve_legacy_clock_ignores_new_constitutional_guard() -> None:
    state = _severe_state(clock=False)
    state["disputes_by_id"]["severe-case"]["vote_counts"] = {"yes": 19}
    result = dispute.apply_dispute(state, _resolve())
    assert result["applied"] == "DISPUTE_RESOLVE"
    assert state["disputes_by_id"]["severe-case"]["stage"] == "resolved"
