"""PR77 DISPUTE_OPEN source attribution and actual runtime behavior dossier.

Source-bound regression evidence only. No accepted V2 digest, historical
replay, constitutional review, producer authorization, or launch authority.
"""

from __future__ import annotations

import copy

import pytest

from scripts.pr77_v2_semantic_review_packet import build_packet
from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute, dispute_open
from weall.runtime.tx_admission import TxEnvelope


def _state(*, clock_enabled: bool = False) -> dict:
    return {
        "height": 25,
        "meta": {"constitutional_clock": {"enabled": clock_enabled}},
        "accounts": {
            "alice": {"poh_tier": 2, "nonce": 0, "banned": False, "locked": False},
            "unverified": {"poh_tier": 0, "nonce": 0, "banned": False, "locked": False},
            "juror": {"poh_tier": 2, "nonce": 0, "banned": False, "locked": False},
        },
        "roles": {"validators": {"active_set": ["juror"]}},
        "content": {
            "posts": {"post-1": {"author": "alice", "visibility": "public"}},
            "comments": {},
        },
        "gov_proposals_by_id": {
            "p-active": {"status": "active"},
            "p-final": {"status": "finalized"},
        },
        "disputes_by_id": {},
        "system_queue": [],
    }


def _env(
    *,
    target_type: str = "content",
    target_id: str = "post-1",
    signer: str = "alice",
    dispute_id: str = "pr77-open",
) -> TxEnvelope:
    return TxEnvelope(
        tx_type="DISPUTE_OPEN",
        signer=signer,
        nonce=1,
        system=False,
        sig="synthetic-not-authenticated",
        payload={
            "dispute_id": dispute_id,
            "target_type": target_type,
            "target_id": target_id,
            "reason": "synthetic source review",
        },
    )


def _run_both(initial_state: dict, tx: TxEnvelope) -> tuple[dict, dict, dict, dict]:
    """Independent state copies detect dispatcher-specific semantic divergence."""
    direct = copy.deepcopy(initial_state)
    dispatched = copy.deepcopy(initial_state)
    direct_meta = dispute_open(direct, copy.deepcopy(tx))
    dispatch_meta = apply_dispute(dispatched, copy.deepcopy(tx))
    return direct, dispatched, direct_meta, dispatch_meta


def test_dispute_open_review_binds_verified_archived_and_current_material() -> None:
    packet = build_packet()
    rows = [row for row in packet["transactions"] if row["tx_type"] == "DISPUTE_OPEN"]
    assert len(rows) == 1
    row = rows[0]
    assert row["stable_id"] == "TX-0200"
    assert row["archive_matches_accepted_digest"] is True
    assert row["archived_compiled_material_digest"] == row["accepted_review_digest"]
    assert row["current_material_digest"] != row["accepted_review_digest"]
    assert row["archived_implementation_source"]["function"] == "apply_dispute"
    assert row["current_implementation_source"]["function"] == "dispute_open"
    assert set(row["changed_field_names"]) == {
        "implementation_source",
        "failure_codes",
        "receipt_contract",
        "state_reads",
        "state_writes",
        "system_followups",
    }
    added = {(entry["code"], entry["reason"]) for entry in row["failure_code_deltas"]["added"]}
    assert {
        ("invalid_payload", "missing_target"),
        ("forbidden", "tier1_required_for_dispute"),
        ("not_found", "proposal_not_found"),
        ("forbidden", "active_proposal_dispute_protected"),
        ("duplicate", "dispute_id_exists"),
    }.issubset(added)
    removed = {(entry["code"], entry["reason"]) for entry in row["failure_code_deltas"]["removed"]}
    assert ("forbidden", "severe_sanction_initial_twenty_votes_unverified") in removed
    assert row["signed_off_for_current_digest"] is False
    assert row["historical_replay_proven"] is False
    assert packet["independent_human_approval_recorded_by_this_packet"] is False
    assert packet["must_not_update_semantic_reviews_automatically"] is True


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
@pytest.mark.parametrize(
    ("target_type", "target_id"),
    [
        ("content", "post-1"),
        ("proposal", "p-final"),
    ],
)
def test_dispute_open_direct_and_dispatcher_identical_success(
    clock_enabled: bool, target_type: str, target_id: str
) -> None:
    st = _state(clock_enabled=clock_enabled)
    direct, dispatched, direct_meta, dispatch_meta = _run_both(
        st, _env(target_type=target_type, target_id=target_id)
    )
    assert direct == dispatched
    assert (
        direct_meta
        == dispatch_meta
        == {
            "applied": "DISPUTE_OPEN",
            "dispute_id": "pr77-open",
        }
    )
    assert direct["disputes_by_id"]["pr77-open"]["target_type"] == target_type
    assert direct["disputes_by_id"]["pr77-open"]["target_id"] == target_id
    assert direct["disputes_by_id"]["pr77-open"]["opened_at_height"] == 25


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
@pytest.mark.parametrize(
    ("target_type", "target_id", "signer", "existing", "expected"),
    [
        ("content", "", "alice", False, ("invalid_payload", "missing_target")),
        ("content", "post-1", "unverified", False, ("forbidden", "tier1_required_for_dispute")),
        ("proposal", "p-missing", "alice", False, ("not_found", "proposal_not_found")),
        (
            "proposal",
            "p-active",
            "alice",
            False,
            ("forbidden", "active_proposal_dispute_protected"),
        ),
        ("content", "post-1", "alice", True, ("duplicate", "dispute_id_exists")),
        (
            "unknown-target",
            "post-1",
            "alice",
            False,
            ("forbidden", "unsupported_dispute_target_type"),
        ),
    ],
)
def test_dispute_open_direct_and_dispatcher_identical_rejection(
    clock_enabled: bool,
    target_type: str,
    target_id: str,
    signer: str,
    existing: bool,
    expected: tuple[str, str],
) -> None:
    seed = _state(clock_enabled=clock_enabled)
    if existing:
        seed["disputes_by_id"]["pr77-open"] = {"id": "pr77-open", "stage": "open"}
    tx = _env(target_type=target_type, target_id=target_id, signer=signer)
    direct = copy.deepcopy(seed)
    dispatched = copy.deepcopy(seed)

    with pytest.raises(DisputeApplyError) as direct_error:
        dispute_open(direct, copy.deepcopy(tx))
    with pytest.raises(DisputeApplyError) as dispatched_error:
        apply_dispute(dispatched, copy.deepcopy(tx))

    assert (direct_error.value.code, direct_error.value.reason) == expected
    assert (dispatched_error.value.code, dispatched_error.value.reason) == expected
    assert direct == dispatched
    # Opening rejection must not smuggle an active review, sanction, or follow-up.
    assert direct["disputes_by_id"] == seed["disputes_by_id"]
    assert direct["system_queue"] == seed["system_queue"]
    assert direct["accounts"] == seed["accounts"]
