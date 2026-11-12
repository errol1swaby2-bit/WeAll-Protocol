"""PR88 diagnostic: panel-filter conflicts vs direct juror transaction gates.

These tests deliberately characterize the current fail-open direct-applier paths.
They are NOT approval of that behavior, proof of admitted signed transactions,
or permission to change consensus semantics without a migration review.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.tx_admission_types import TxEnvelope


def _state_with_conflicted_reviewer(conflict_field: str = "party_ids") -> dict:
    reviewer = "@juror"
    case = {
        "id": "case-1",
        "target_type": "content",
        "target_id": "post-123",
        "reported_by": "@reporter",
        conflict_field: ["juror"],
        "stage": "juror_review",
        "jurors": {reviewer: {"status": "assigned"}},
        "assigned_jurors": [reviewer],
        "eligible_juror_ids": [reviewer],
    }
    return {
        "height": 12,
        "accounts": {reviewer: {}, "@reporter": {}},
        "roles": {
            "jurors": {
                "by_id": {
                    reviewer: {
                        "account_id": reviewer,
                        "enrolled": True,
                        "active": True,
                        "responsibilities": {
                            "reviewer": {
                                "dispute_review": {"opted_in": True, "active": True}
                            }
                        },
                    }
                },
                "active_set": [reviewer],
            }
        },
        "disputes_by_id": {"case-1": case},
    }


@pytest.mark.parametrize(
    "conflict_field",
    (
        "party_ids",
        "beneficiary_ids",
        "material_connection_ids",
        "financial_connection_ids",
    ),
)
def test_panel_filter_excludes_conflict_but_direct_reviewer_gate_currently_does_not(
    conflict_field: str,
) -> None:
    state = _state_with_conflicted_reviewer(conflict_field)
    case = state["disputes_by_id"]["case-1"]
    assert "@juror" in dispute._dispute_conflict_account_ids(state, case)
    assert dispute._filter_active_dispute_reviewers(state, ["@juror"], case) == []
    assert case["conflict_policy"] == "constitutional_material_conflicts_excluded"

    # Characterization of the unresolved gap; do NOT treat this as desired policy.
    assert dispute._require_dispute_reviewer_lane(state, "@juror", case) == "@juror"


def test_direct_system_assignment_currently_overrides_material_conflict_filter() -> None:
    state = _state_with_conflicted_reviewer()
    case = state["disputes_by_id"]["case-1"]
    case["jurors"] = {}
    case["assigned_jurors"] = []
    case["eligible_juror_ids"] = []
    env = TxEnvelope(
        tx_type="DISPUTE_JUROR_ASSIGN",
        signer="SYSTEM",
        system=True,
        nonce=4,
        payload={"dispute_id": "case-1", "juror": "@juror"},
    )

    # This is a direct-applier SYSTEM envelope, not admitted queue-origin proof.
    result = dispute._apply_dispute_juror_assign(state, env)
    assert result["applied"] == "DISPUTE_JUROR_ASSIGN"
    assert case["jurors"]["@juror"]["status"] == "assigned"
    assert "@juror" in case["assigned_jurors"]


def test_stale_materially_conflicted_assignment_currently_reaches_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state_with_conflicted_reviewer("financial_connection_ids")
    before = deepcopy(state["disputes_by_id"]["case-1"])
    assert before["jurors"]["@juror"]["status"] == "assigned"

    # Stub only the downstream event write to isolate the authorization gate.
    monkeypatch.setattr(
        dispute,
        "_record_dispute_juror_reputation_event",
        lambda *_args, **_kwargs: {
            "event_id": "test-only-event",
            "canonical_reputation_event_id": "test-only-canonical-event",
        },
    )
    result = dispute._apply_dispute_juror_accept(
        state,
        TxEnvelope(
            tx_type="DISPUTE_JUROR_ACCEPT",
            signer="@juror",
            nonce=5,
            payload={"dispute_id": "case-1"},
        ),
    )
    assert result["applied"] == "DISPUTE_JUROR_ACCEPT"
    assert state["disputes_by_id"]["case-1"]["jurors"]["@juror"]["status"] == "accepted"


def test_specific_reporter_guard_remains_fail_closed() -> None:
    state = _state_with_conflicted_reviewer()
    case = state["disputes_by_id"]["case-1"]
    case["reported_by"] = "juror"
    with pytest.raises(dispute.DisputeApplyError) as error:
        dispute._require_dispute_reviewer_lane(state, "@juror", case)
    assert (error.value.code, error.value.reason) == (
        "forbidden",
        "juror_conflict_reporter",
    )
