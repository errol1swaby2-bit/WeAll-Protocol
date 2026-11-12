"""PR77 strict fresh appeal-panel formation and failed-appeal atomicity.

These are deterministic domain transitions on synthetic ledger state. They do
not authenticate a public PoH pool, signatures, independent BFT or S4 sanction
authority. Signed executor replay is covered separately.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    SystemQueueCorruptionError,
    build_system_queue_lookup,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _state(*, jurors: int = 17) -> dict:
    roster = [f"@juror-{n:02d}" for n in range(jurors)]
    active = {
        "active": True,
        "responsibilities": {"reviewer": {"dispute_review": {"active": True, "opted_in": True}}},
    }
    return {
        "chain_id": "strict-local-appeal-fixture",
        "height": 25,
        "meta": {"constitutional_clock": {"enabled": True}},
        "params": {
            "mode": "controlled-testnet",
            "m3_civic_governance_strict": True,
        },
        "accounts": {
            "@subject": {"poh_tier": 2, "banned": False, "locked": False},
            "@outsider": {"poh_tier": 2, "banned": False, "locked": False},
            **{account: {"poh_tier": 2, "banned": False, "locked": False} for account in roster},
        },
        "roles": {
            "jurors": {
                "active_set": list(roster),
                "by_id": {account: deepcopy(active) for account in roster},
            }
        },
        "disputes_by_id": {
            "ordinary-account-review": {
                "id": "ordinary-account-review",
                "target_type": "account",
                "target_id": "@subject",
                "target_owner": "@subject",
                "stage": "appeal_window",
                "resolved": True,
                "appeal_allowed_accounts": ["@subject"],
                "appeal_deadline_height": 80,
                "assigned_jurors": roster[:7],
                "substitute_juror_ids": roster[7:9],
                "panel_round": 1,
                "appeals": [],
                "votes": {},
                "jurors": {},
            }
        },
        "system_queue": [],
    }


def _appeal(signer: str = "@subject", *, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(
        tx_type="DISPUTE_APPEAL",
        signer=signer,
        nonce=nonce,
        payload={"dispute_id": "ordinary-account-review", "reason": "Synthetic independent appeal"},
        sig="synthetic-not-verified",
        system=False,
    )


def _case(state: dict) -> dict:
    return state["disputes_by_id"]["ordinary-account-review"]


def test_insufficient_fresh_strict_panel_records_pending_appeal() -> None:
    # Seven original reviewers plus two substitutes leave only eight fresh
    # candidates; nine are required. Filing remains valid and durable.
    state = _state(jurors=17)
    result = apply_dispute(state, _appeal())
    case = _case(state)
    assert result["applied"] == "DISPUTE_APPEAL"
    assert result["appeal_panel_status"] == "insufficient_reviewer_pool"
    assert case["stage"] == "appeal_pending_panel"
    assert case["appeal_panel_blocked_reason"] == "insufficient_fresh_appeal_panel"
    assert case["appeal_pending_since_height"] == 25
    assert case["appeal_panel_required_size"] == 7
    assert case["appeal_substitute_required_count"] == 2
    assert case["appeal_panel_available_candidate_count"] == 8
    assert case["appeals"][0]["by"] == "@subject"
    assert case["appeals"][0]["at_nonce"] == 1
    assert case["appeals"][0]["height"] == 25
    assert case["original_panel_juror_ids"] == [f"@juror-{n:02d}" for n in range(7)]
    assert case["original_substitute_juror_ids"] == ["@juror-07", "@juror-08"]
    assert case["assigned_jurors"] == []
    assert case["eligible_juror_ids"] == []
    assert case["jurors"] == {}
    assert state["system_queue"] == []

    # Even long after the original filing deadline, a lodged appeal cannot
    # automatically expire or enqueue the original-result final receipt.
    state["height"] = 100
    before = deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=101) == 0
    assert state == before
    assert state["system_queue"] == []


def test_pending_appeal_assigns_complete_fresh_panel_when_pool_grows() -> None:
    state = _state(jurors=17)
    apply_dispute(state, _appeal())
    # Model an independent reviewer joining replicated role/account state.
    state["height"] = 81
    new_juror = "@juror-17"
    state["accounts"][new_juror] = {
        "poh_tier": 2,
        "banned": False,
        "locked": False,
    }
    state["roles"]["jurors"]["active_set"].append(new_juror)
    state["roles"]["jurors"]["by_id"][new_juror] = deepcopy(
        state["roles"]["jurors"]["by_id"]["@juror-00"]
    )
    replica = deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=82) == 0
    assert tick_dispute_lifecycle(replica, next_height=82) == 0
    assert state == replica

    case = _case(state)
    assert case["stage"] == "appeal_review"
    assert case["appeal_panel_status"] == "assigned"
    assert case["appeal_panel_round"] == 2
    assert case["appeal_panel_assigned_at_height"] == 82
    assert case["appeal_pending_since_height"] == 25
    assert case["appeals"][0]["height"] == 25
    assert "appeal_panel_blocked_reason" not in case
    assert len(case["appeal_panel_juror_ids"]) == 7
    assert len(case["appeal_substitute_juror_ids"]) == 2
    original = case["original_panel_juror_ids"] + case["original_substitute_juror_ids"]
    fresh = case["appeal_panel_juror_ids"] + case["appeal_substitute_juror_ids"]
    assert set(original).isdisjoint(fresh)
    assert len(set(fresh)) == 9
    assert "@subject" not in fresh
    assert case["assigned_jurors"] == case["appeal_panel_juror_ids"]
    assert all(record["assigned_at_nonce"] == 1 for record in case["jurors"].values())
    before_repeat = deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=83) == 0
    assert state == before_repeat


def test_pending_appeal_blocks_stale_system_final_receipt_without_mutation() -> None:
    state = _state(jurors=17)
    apply_dispute(state, _appeal())
    state["height"] = 100
    before = deepcopy(state)
    forged = TxEnvelope(
        tx_type="DISPUTE_FINAL_RECEIPT",
        signer="SYSTEM",
        nonce=101,
        system=True,
        payload={
            "dispute_id": "ordinary-account-review",
            "receipt_id": "stale-after-appeal",
            "resolution": {"outcome": "report_upheld"},
        },
    )
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(state, forged)
    assert exc.value.reason == "appeal_pending_panel"
    assert state == before
    assert "dispute_receipts" not in state


def test_fresh_strict_appeal_panel_is_disjoint_deterministic_and_recorded_once() -> None:
    state = _state(jurors=18)
    independent = deepcopy(state)
    outcome = apply_dispute(state, _appeal())
    second = apply_dispute(independent, _appeal())
    assert outcome == second
    assert state == independent
    case = _case(state)
    assert outcome["applied"] == "DISPUTE_APPEAL"
    assert case["stage"] == "appeal_review"
    assert case["appeal_panel_round"] == 2
    assert case["appeal_panel_status"] == "assigned"
    assert len(case["appeal_panel_juror_ids"]) == 7
    assert len(case["appeal_substitute_juror_ids"]) == 2
    assert len(set(case["appeal_panel_juror_ids"] + case["appeal_substitute_juror_ids"])) == 9
    assert set(case["appeal_panel_juror_ids"] + case["appeal_substitute_juror_ids"]).isdisjoint(
        set(case["original_panel_juror_ids"] + case["original_substitute_juror_ids"])
    )
    assert "@subject" not in case["appeal_panel_juror_ids"]
    assert case["required_votes"] > 0
    assert case["appeals"] == [
        {
            "by": "@subject",
            "at_nonce": 1,
            "height": 25,
            "payload": {
                "dispute_id": "ordinary-account-review",
                "reason": "Synthetic independent appeal",
            },
        }
    ]
    assert state["system_queue"] == []


@pytest.mark.parametrize("jurors", [17, 18])
def test_duplicate_and_unauthorized_appeals_do_not_mutate_strict_state(jurors: int) -> None:
    state = _state(jurors=jurors)
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as outsider:
        apply_dispute(state, _appeal("@outsider"))
    assert outsider.value.reason == "appeal_not_target_owner"
    assert state == before

    apply_dispute(state, _appeal())
    after_first = deepcopy(state)
    with pytest.raises(DisputeApplyError) as duplicate:
        apply_dispute(state, _appeal(nonce=2))
    assert duplicate.value.reason == "appeal_already_filed"
    assert state == after_first


def test_expired_strict_appeal_window_does_not_mutate_state() -> None:
    state = _state(jurors=18)
    state["height"] = 81
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(state, _appeal())
    assert exc.value.reason == "appeal_window_closed"
    assert state == before


def _system_final_receipt(
    *, appeal_resolution: dict | None = None, resolution: dict | None = None
) -> TxEnvelope:
    payload = {
        "dispute_id": "ordinary-account-review",
        "receipt_id": "synthetic-appeal-final",
    }
    if appeal_resolution is not None:
        payload["appeal_resolution"] = appeal_resolution
    if resolution is not None:
        payload["resolution"] = resolution
    return TxEnvelope(
        tx_type="DISPUTE_FINAL_RECEIPT",
        signer="SYSTEM",
        nonce=99,
        system=True,
        payload=payload,
        sig="synthetic-not-authenticated",
    )


@pytest.mark.parametrize("stage", ["appeal_review", "appealed"])
def test_unresolved_fresh_appeal_cannot_be_finalized_by_claimed_system_decision(
    stage: str,
) -> None:
    state = _state(jurors=18)
    apply_dispute(state, _appeal())
    case = _case(state)
    case["stage"] = stage
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(
            state,
            _system_final_receipt(appeal_resolution={"decision": "reverse"}),
        )
    assert exc.value.reason == "appeal_panel_decision_not_finalized"
    assert state == before
    assert "dispute_receipts" not in state
    assert "dispute_juror_accountability" not in state


def test_finalizing_marker_without_reached_appeal_panel_cannot_finalize() -> None:
    state = _state(jurors=18)
    apply_dispute(state, _appeal())
    _case(state)["stage"] = "finalizing"
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(
            state,
            _system_final_receipt(appeal_resolution={"decision": "reverse"}),
        )
    assert exc.value.reason == "appeal_panel_decision_unverified"
    assert state == before


@pytest.mark.parametrize(
    ("overrides", "expected_reason"),
    [
        (
            {"appeal_resolution": {"decision": "uphold"}},
            "appeal_resolution_mismatch",
        ),
        (
            {"resolution": {"actions": [{"tx_type": "CONTENT_VISIBILITY_SET"}]}},
            "appeal_original_resolution_override",
        ),
    ],
)
def test_finalizing_appeal_cannot_override_stored_panel_decision(
    overrides: dict, expected_reason: str
) -> None:
    state = _state(jurors=18)
    apply_dispute(state, _appeal())
    case = _case(state)
    case["stage"] = "finalizing"
    case["appeal_panel_result"] = {
        "reached": True,
        "resolution": {"decision": "reverse"},
    }
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(state, _system_final_receipt(**overrides))
    assert exc.value.reason == expected_reason
    assert state == before


def test_matching_reached_panel_decision_can_finalize_synthetic_appeal() -> None:
    state = _state(jurors=18)
    apply_dispute(state, _appeal())
    case = _case(state)
    case["stage"] = "finalizing"
    case["appeal_panel_result"] = {
        "reached": True,
        "resolution": {"decision": "reverse"},
    }
    result = apply_dispute(
        state,
        _system_final_receipt(appeal_resolution={"decision": "reverse"}),
    )
    assert result["applied"] == "DISPUTE_FINAL_RECEIPT"
    assert result["appeal_finalization"]["decision"] == "reverse"
    assert case["stage"] == "finalized"
    assert case["final_resolution"]["actions"] == []
    assert (
        state["dispute_receipts"]["synthetic-appeal-final"]["appeal_finalization"]["decision"]
        == "reverse"
    )


def _appeal_resolved_state_for_queue() -> dict:
    """Synthetic adjudication state; no independently verified ballot evidence."""
    state = _state(jurors=18)
    apply_dispute(state, _appeal())
    case = _case(state)
    case["stage"] = "appeal_resolved"
    case["appeal_panel_result"] = {
        "reached": True,
        "resolution": {"decision": "reverse"},
    }
    return state


def _appeal_receipt_canon() -> TxIndex:
    root = Path(__file__).resolve().parents[1]
    return TxIndex.load_from_file(str(root / "generated" / "tx_index.json"))


def _emit_appeal_receipt() -> tuple[dict, TxIndex, TxEnvelope]:
    state = _appeal_resolved_state_for_queue()
    canon = _appeal_receipt_canon()
    assert tick_dispute_lifecycle(state, next_height=26) == 1
    assert _case(state)["stage"] == "finalizing"
    assert len(state["system_queue"]) == 1
    envelope = system_tx_emitter(state, canon, next_height=26, phase="pre")
    assert len(envelope) == 1
    return state, canon, envelope[0]


def test_reached_appeal_queues_exact_pre_phase_system_receipt() -> None:
    state, canon, receipt = _emit_appeal_receipt()
    case = _case(state)
    queue = state["system_queue"][0]
    parent = "dispute:ordinary-account-review:appeal-panel-finalize:2"

    assert case["appeal_panel_result"]["resolution"] == {"decision": "reverse"}
    assert receipt.tx_type == queue["tx_type"] == "DISPUTE_FINAL_RECEIPT"
    assert receipt.system is True
    assert receipt.signer == queue["signer"] == "SYSTEM"
    assert receipt.parent == queue["parent"] == parent
    assert queue["phase"] == "pre"
    assert queue["due_height"] == queue["emitted_height"] == 26
    assert receipt.payload["receipt_id"] == f"receipt:{parent}"
    assert receipt.payload["_parent_ref"] == parent
    assert receipt.payload["_due_height"] == 26
    assert receipt.payload["_system_queue_id"] == queue["queue_id"]
    assert receipt.payload["appeal_resolution"] == {"decision": "reverse"}
    assert validate_system_tx_queue_binding(state, canon, receipt, next_height=26, phase="pre") == (
        True,
        "",
    )
    assert validate_system_tx_queue_binding(
        state,
        canon,
        receipt,
        next_height=26,
        phase="pre",
        queue_objects_by_id=build_system_queue_lookup(state),
    ) == (True, "")


def test_reached_appeal_pre_scheduler_and_emitter_reproduce_identical_state_root() -> None:
    seed = _appeal_resolved_state_for_queue()
    canon = _appeal_receipt_canon()
    leader = deepcopy(seed)
    follower = deepcopy(seed)

    for replica in (leader, follower):
        assert tick_dispute_lifecycle(replica, next_height=26) == 1
        emitted = system_tx_emitter(replica, canon, next_height=26, phase="pre")
        assert len(emitted) == 1

    assert leader == follower
    assert compute_state_root(leader) == compute_state_root(follower)
    assert build_system_queue_lookup(leader) == build_system_queue_lookup(follower)


def test_unreached_appeal_panel_never_queues_final_receipt() -> None:
    state = _appeal_resolved_state_for_queue()
    _case(state)["appeal_panel_result"]["reached"] = False
    before = deepcopy(state)

    assert tick_dispute_lifecycle(state, next_height=26) == 0
    assert state == before
    assert state["system_queue"] == []


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("missing_queue_id", "missing_system_queue_id"),
        ("unknown_queue_id", "unknown_system_queue_id"),
        ("changed_decision", "system_queue_payload_mismatch"),
        ("changed_receipt_id", "system_queue_payload_mismatch"),
        ("changed_due_height", "system_payload_due_height_mismatch"),
        ("changed_parent", "system_queue_parent_mismatch"),
        ("changed_signer", "system_queue_signer_mismatch"),
        ("changed_tx_type", "system_queue_tx_type_mismatch"),
        ("changed_phase", "system_queue_phase_mismatch"),
    ],
)
def test_appeal_final_receipt_rejects_forged_queue_provenance(
    mutation: str, expected_reason: str
) -> None:
    state, canon, receipt = _emit_appeal_receipt()
    block_env = receipt.to_json()
    payload = block_env["payload"]
    phase = "pre"

    if mutation == "missing_queue_id":
        payload.pop("_system_queue_id")
    elif mutation == "unknown_queue_id":
        payload["_system_queue_id"] = "unknown-appeal-queue"
    elif mutation == "changed_decision":
        payload["appeal_resolution"] = {"decision": "uphold"}
    elif mutation == "changed_receipt_id":
        payload["receipt_id"] = "receipt:forged"
    elif mutation == "changed_due_height":
        payload["_due_height"] = 27
    elif mutation == "changed_parent":
        block_env["parent"] = "forged-parent"
    elif mutation == "changed_signer":
        block_env["signer"] = "@forger"
    elif mutation == "changed_tx_type":
        block_env["tx_type"] = "DISPUTE_RESOLVE"
    elif mutation == "changed_phase":
        phase = "post"

    snapshot = deepcopy(state)
    checked = TxEnvelope.from_json(block_env)
    assert validate_system_tx_queue_binding(state, canon, checked, next_height=26, phase=phase) == (
        False,
        expected_reason,
    )
    assert state == snapshot


def test_tampered_appeal_queue_record_is_canonical_corruption() -> None:
    state, _, _ = _emit_appeal_receipt()
    state["system_queue"][0]["payload"]["appeal_resolution"]["decision"] = "uphold"
    with pytest.raises(SystemQueueCorruptionError, match="system_queue_item_queue_id_mismatch"):
        build_system_queue_lookup(state)
