"""PR88 diagnostic: panel-filter conflicts vs direct juror transaction gates.

These tests deliberately characterize the current fail-open direct-applier paths.
They are NOT approval of that behavior, proof of admitted signed transactions,
or permission to change consensus semantics without a migration review.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from weall.runtime.apply import dispute
from weall.runtime.system_tx_engine import (
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


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
                            "reviewer": {"dispute_review": {"opted_in": True, "active": True}}
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


@pytest.mark.parametrize("strict_profile", (False, True))
def test_stale_materially_conflicted_assignment_currently_reaches_acceptance(
    monkeypatch: pytest.MonkeyPatch, strict_profile: bool
) -> None:
    state = _state_with_conflicted_reviewer("financial_connection_ids")
    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: strict_profile)
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


def test_strict_panel_rejects_material_conflict_while_legacy_selection_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state_with_conflicted_reviewer("financial_connection_ids")
    case = state["disputes_by_id"]["case-1"]
    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    strict = dispute.select_dispute_panel(state, case, ["@juror"])
    assert "@juror" in strict["conflicted_juror_ids"]
    assert "@juror" in strict["excluded_juror_ids"]
    assert strict["panel"] == []

    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: False)
    legacy = dispute.select_dispute_panel(state, case, ["@juror"])
    assert legacy["panel"] == ["@juror"]
    assert legacy["status"] == "legacy_all_eligible_reviewers"
    assert legacy["strict"] is False


def test_canonical_system_queue_binding_is_not_dispute_conflict_authorization() -> None:
    """A genuine queue ID binds the envelope, not its origin's legitimacy or juror eligibility."""
    state = _state_with_conflicted_reviewer("material_connection_ids")
    case = state["disputes_by_id"]["case-1"]
    assert "@juror" in dispute._dispute_conflict_account_ids(state, case)
    case["jurors"] = {}
    case["assigned_jurors"] = []
    case["eligible_juror_ids"] = []
    qid = enqueue_system_tx(
        state,
        tx_type="DISPUTE_JUROR_ASSIGN",
        payload={"dispute_id": "case-1", "juror": "@juror"},
        due_height=13,
        signer="SYSTEM",
        once=True,
        parent="CONTENT_ESCALATE_TO_DISPUTE",
        phase="post",
    )
    canon = TxIndex.load_from_file(
        str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )
    due = system_tx_emitter(state, canon, next_height=13, phase="post")
    assert len(due) == 1
    emitted = due[0]
    assert emitted.payload["_system_queue_id"] == qid
    assert emitted.payload["_due_height"] == 13
    assert validate_system_tx_queue_binding(
        state, canon, emitted, next_height=13, phase="post"
    ) == (True, "")
    # This bypass is after test-created queue insertion; no signed origin is proven.
    assert dispute._apply_dispute_juror_assign(state, emitted)["juror"] == "@juror"
    assert case["jurors"]["@juror"]["status"] == "assigned"


def test_forged_dispute_assignment_cannot_bypass_system_queue_binding() -> None:
    state = _state_with_conflicted_reviewer()
    canon = TxIndex.load_from_file(
        str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )
    forged = TxEnvelope(
        tx_type="DISPUTE_JUROR_ASSIGN",
        signer="SYSTEM",
        system=True,
        parent="CONTENT_ESCALATE_TO_DISPUTE",
        payload={"dispute_id": "case-1", "juror": "@juror"},
    )
    assert validate_system_tx_queue_binding(state, canon, forged, next_height=13, phase="post") == (
        False,
        "missing_system_queue_id",
    )
    forged.payload["_system_queue_id"] = "unknown-queue"
    forged.payload["_due_height"] = 13
    assert validate_system_tx_queue_binding(state, canon, forged, next_height=13, phase="post") == (
        False,
        "unknown_system_queue_id",
    )


@pytest.mark.parametrize(
    "conflict_field",
    (
        "party_ids",
        "beneficiary_ids",
        "material_connection_ids",
        "financial_connection_ids",
    ),
)
@pytest.mark.parametrize(
    "tx_type", ("DISPUTE_JUROR_ASSIGN", "DISPUTE_JUROR_ACCEPT", "DISPUTE_VOTE_SUBMIT")
)
def test_explicit_strict_v2_conflict_gate_rejects_before_mutating_any_state(
    monkeypatch: pytest.MonkeyPatch, tx_type: str, conflict_field: str
) -> None:
    state = _state_with_conflicted_reviewer(conflict_field)
    state["params"] = {"dispute_material_conflict_gate_version": 2}
    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    monkeypatch.setattr(
        dispute,
        "_require_active_dispute_ballot_profile",
        lambda *_args, **_kwargs: {"strict": True, "active": True},
    )
    if tx_type == "DISPUTE_JUROR_ASSIGN":
        state["disputes_by_id"]["case-1"]["jurors"] = {}
        state["disputes_by_id"]["case-1"]["assigned_jurors"] = []
        env = TxEnvelope(
            tx_type=tx_type,
            signer="SYSTEM",
            system=True,
            nonce=6,
            payload={"dispute_id": "case-1", "juror": "@juror"},
        )
    else:
        env = TxEnvelope(
            tx_type=tx_type,
            signer="@juror",
            nonce=6,
            payload={"dispute_id": "case-1", "vote": "no"},
        )
    before = deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as error:
        dispute.apply_dispute(state, env)
    assert (error.value.code, error.value.reason) == ("forbidden", "juror_conflict_material")
    assert error.value.details["gate_version"] == 2
    assert state == before


@pytest.mark.parametrize("unsupported", (0, 3, True, "2", None))
def test_strict_invalid_material_conflict_gate_version_fails_closed(
    monkeypatch: pytest.MonkeyPatch, unsupported: object
) -> None:
    state = _state_with_conflicted_reviewer("financial_connection_ids")
    state["params"] = {"dispute_material_conflict_gate_version": unsupported}
    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    before = deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as error:
        dispute._apply_dispute_juror_accept(
            state,
            TxEnvelope(
                tx_type="DISPUTE_JUROR_ACCEPT",
                signer="@juror",
                nonce=6,
                payload={"dispute_id": "case-1"},
            ),
        )
    assert (error.value.code, error.value.reason) == (
        "forbidden",
        "unsupported_dispute_material_conflict_gate_version",
    )
    assert state == before


def test_strict_legacy_v1_default_does_not_silently_rewrite_existing_conflict_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state_with_conflicted_reviewer("financial_connection_ids")
    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    assert "dispute_material_conflict_gate_version" not in state.get("params", {})
    assert (
        dispute._require_dispute_reviewer_lane(state, "@juror", state["disputes_by_id"]["case-1"])
        == "@juror"
    )
