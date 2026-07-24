from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from weall.runtime.account_recovery_policy import (
    RECOVERY_FAILED_WINDOW_BLOCKS,
    RECOVERY_REQUEST_COOLDOWN_BLOCKS,
    RECOVERY_RESTRICTION_BLOCKS,
)
from weall.runtime.account_recovery_scheduler import schedule_account_recovery_system_txs
from weall.runtime.domain_apply import apply_tx_atomic
from weall.runtime.errors import ApplyError
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.evidence_lifecycle import (
    EVIDENCE_DELETE_COMPLETION_BLOCKS,
    EVIDENCE_DELETE_RETRY_BLOCKS,
    EVIDENCE_RETENTION_BLOCKS,
    close_case_evidence,
    evidence_record,
    mark_reviewer_accessible,
    process_evidence_lifecycle,
    record_provider_deletion_attestation,
    register_encrypted_evidence,
)
from weall.runtime.poh.state import (
    POH_STATUS_ACTIVE,
    TIER2_REMINDER_OFFSETS,
    process_tier2_lifecycle,
    set_account_poh_status,
    tier2_lifecycle_fields,
)
from weall.runtime.recovery_review import (
    CONTINUITY_APPROVAL_THRESHOLD,
    CONTINUITY_PANEL_SIZE,
    REVERSAL_APPROVAL_THRESHOLD,
    REVERSAL_PANEL_SIZE,
)
from weall.runtime.tier2_responsibility import SAFE_WITHDRAWAL_BLOCKS
from weall.runtime.tx_contracts import load_default_tx_index
from weall.runtime.tx_schema import validate_tx_envelope


def _state(*, height: int = 100, reviewer_count: int = 0) -> dict:
    state = {
        "chain_id": "weall-m2-complete-test",
        "network_id": "weall-m2-complete-test",
        "height": height,
        "time": 0,
        "last_block_ts_ms": 0,
        "params": {
            "guardian_recovery_new_admission": False,
            "require_signatures": False,
            "poh": {
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_expiry_window_blocks": 100,
            },
        },
        "accounts": {},
        "roles": {"jurors": {"active_set": []}},
        "poh": {},
    }
    for index in range(1, reviewer_count + 1):
        reviewer_id = f"@reviewer{index:02d}"
        state["accounts"][reviewer_id] = _account(f"reviewer-key-{index}", tier=2)
        state["roles"]["jurors"]["active_set"].append(reviewer_id)
    return state


def _account(pubkey: str, *, tier: int = 0, recovery_pubkey: str | None = None) -> dict:
    key_id = f"key:{pubkey}"
    recovery = {
        "mode": "offline_key" if recovery_pubkey else None,
        "config": None,
        "offline_key": None,
        "prior_offline_keys": [],
        "proposals": {},
        "requests": {},
        "authority_generation": 0,
        "failed_attempt_heights": [],
        "history": [],
    }
    if recovery_pubkey:
        recovery["authority_generation"] = 1
        recovery["offline_key"] = {
            "pubkey": recovery_pubkey,
            "sig_profile": "pq-mldsa-v1",
            "key_id": f"key:{recovery_pubkey}",
            "generation": 1,
            "registered_height": 1,
        }
    return {
        "nonce": 0,
        "account_type": "human",
        "poh_tier": tier,
        "poh_status": POH_STATUS_ACTIVE if tier else None,
        "banned": False,
        "locked": False,
        "reputation": "100",
        "keys": {
            "by_id": {
                key_id: {
                    "key_id": key_id,
                    "pubkey": pubkey,
                    "sig_profile": "pq-mldsa-v1",
                    "key_type": "main",
                    "revoked": False,
                }
            }
        },
        "active_keys": [pubkey],
        "pubkeys": [pubkey],
        "pubkey": pubkey,
        "devices": {"by_id": {}},
        "session_keys": {},
        "recovery": recovery,
    }


def _apply(
    state: dict,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> dict:
    tx = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "sig": "direct-test",
        "chain_id": state["chain_id"],
    }
    if system:
        tx["system"] = True
        tx["parent"] = parent or "SYSTEM_PARENT"
    return apply_tx_atomic(copy.deepcopy(state), tx)


def _continuity_payload(
    request_id: str, *, method: str = "continuity", challenged: str | None = None, suffix: str = "a"
) -> dict:
    payload = {
        "request_id": request_id,
        "target": "@alice",
        "method": method,
        "new_pubkey": f"new-authority-{suffix}",
        "new_sig_profile": "pq-mldsa-v1",
        "new_recovery_pubkey": f"new-recovery-{suffix}",
        "new_recovery_sig_profile": "pq-mldsa-v1",
        "new_recovery_key_commitment": "sha256:" + "9" * 64,
        "evidence_class_commitments": [
            {"class_id": "government_record", "commitment": "sha256:" + "1" * 64},
            {"class_id": "historical_account_activity", "commitment": "sha256:" + "2" * 64},
        ],
        "strong_anchor_commitment": "sha256:" + "3" * 64,
        "social_attestation_commitments": ["sha256:" + "4" * 64],
        "evidence_policy_version": "m2-v1",
        "recovery_evidence": [
            {
                "evidence_id": f"recovery-evidence:{request_id}:1",
                "class_id": "government_record",
                "strong_anchor": True,
                "ciphertext_cid": f"bafy-recovery-{request_id}-1",
                "ciphertext_commitment": "sha256:" + "a" * 64,
                "encryption_context_commitment": "sha256:" + "b" * 64,
                "provider_ids": ["@provider1"],
            },
            {
                "evidence_id": f"recovery-evidence:{request_id}:2",
                "class_id": "historical_account_activity",
                "strong_anchor": False,
                "ciphertext_cid": f"bafy-recovery-{request_id}-2",
                "ciphertext_commitment": "sha256:" + "c" * 64,
                "encryption_context_commitment": "sha256:" + "d" * 64,
                "provider_ids": ["@provider1"],
            },
        ],
    }
    if challenged:
        payload["challenged_request_id"] = challenged
    return payload


def _approve_recovery_panel(state: dict, request_id: str, count: int) -> dict:
    request = state["accounts"]["@alice"]["recovery"]["requests"][request_id]
    if request.get("evidence_access_ready") is not True:
        principals = ["@alice", *list(request["assigned_reviewers"])]
        for evidence_id in request.get("evidence_ids", []):
            subject_nonce = int(state["accounts"]["@alice"]["nonce"]) + 1
            state = _apply(
                state,
                "ACCOUNT_RECOVERY_APPROVE",
                "@alice",
                subject_nonce,
                {
                    "request_id": request_id,
                    "decision": "evidence_bind",
                    "evidence_id": evidence_id,
                    "key_envelope_commitments": _envelopes(principals),
                },
            )
        request = state["accounts"]["@alice"]["recovery"]["requests"][request_id]
    for reviewer_id in list(request["assigned_reviewers"])[:count]:
        reviewer_nonce = int(state["accounts"][reviewer_id]["nonce"]) + 1
        state = _apply(
            state,
            "ACCOUNT_RECOVERY_APPROVE",
            reviewer_id,
            reviewer_nonce,
            {
                "request_id": request_id,
                "decision": "approve",
                "review_commitment": "sha256:" + "5" * 64,
            },
        )
    return state


def _encrypted_declare_payload(case_id: str, evidence_id: str) -> dict:
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_commitment": "sha256:" + "1" * 64,
        "response_commitment": "sha256:" + "2" * 64,
        "encrypted": True,
        "encryption_algorithm": "aes-256-gcm",
        "ciphertext_cid": f"bafy-{evidence_id}",
        "ciphertext_commitment": "sha256:" + "3" * 64,
        "encryption_context_commitment": "sha256:" + "4" * 64,
        "ciphertext_size": 512,
        "provider_ids": ["@provider1"],
    }


def _envelopes(principals: list[str]) -> dict:
    return {
        principal: {
            "algorithm": "ml-kem-768+aes-256-gcm",
            "kem_ciphertext_commitment": "sha256:" + "6" * 64,
            "wrapped_key_commitment": "sha256:" + "7" * 64,
            "envelope_commitment": "sha256:" + "8" * 64,
        }
        for principal in principals
    }


def test_v2_registration_requires_independent_recovery_and_evidence_kem_keys() -> None:
    state = _state()
    state["params"]["require_recovery_key_at_account_register"] = True
    state["params"]["require_evidence_kem_at_account_register"] = True

    with pytest.raises(ApplyError) as missing:
        _apply(
            state,
            "ACCOUNT_REGISTER",
            "@alice",
            1,
            {"pubkey": "main-key", "sig_profile": "pq-mldsa-v1"},
        )
    assert missing.value.reason == "recovery_key_required_at_account_register"

    kem_pubkey = base64.b64encode(b"k" * 1184).decode("ascii")
    state = _apply(
        state,
        "ACCOUNT_REGISTER",
        "@alice",
        1,
        {
            "pubkey": "main-key",
            "sig_profile": "pq-mldsa-v1",
            "recovery_pubkey": "offline-key",
            "recovery_sig_profile": "pq-mldsa-v1",
            "evidence_kem_pubkey": kem_pubkey,
            "evidence_kem_algorithm": "ml-kem-768",
        },
    )
    account = state["accounts"]["@alice"]
    assert account["recovery"]["offline_key"]["pubkey"] == "offline-key"
    assert account["evidence_encryption"]["public_key"] == kem_pubkey

    with pytest.raises(ApplyError) as active_rotation:
        _apply(
            state,
            "ACCOUNT_RECOVERY_CONFIG_SET",
            "@alice",
            2,
            {"recovery_pubkey": "attacker-key", "recovery_sig_profile": "pq-mldsa-v1"},
        )
    assert active_rotation.value.reason == "recovery_rotation_requires_offline_key"


def _social_continuity_payload(request_id: str) -> dict:
    payload = _continuity_payload(request_id, suffix=request_id)
    payload["evidence_class_commitments"][1] = {
        "class_id": "social_continuity_attestations",
        "commitment": "sha256:" + "6" * 64,
    }
    payload["recovery_evidence"][1]["class_id"] = "social_continuity_attestations"
    return payload


def _social_attest(
    state: dict,
    request_id: str,
    reviewer_index: int,
    *,
    household_index: int | None = None,
    reason_code: str = "no_financial_or_institutional_dependency_v1",
    include_independence: bool = True,
) -> dict:
    reviewer_id = f"@reviewer{reviewer_index:02d}"
    payload = {
        "request_id": request_id,
        "decision": "social_attest",
        "attestation_commitment": "sha256:" + f"{reviewer_index:064x}",
        "household_commitment": "sha256:"
        + f"{(household_index if household_index is not None else reviewer_index + 100):064x}",
        "reason_code": reason_code,
    }
    if include_independence:
        payload["independence_commitment"] = "sha256:" + f"{reviewer_index + 200:064x}"
    return _apply(
        state,
        "ACCOUNT_RECOVERY_APPROVE",
        reviewer_id,
        int(state["accounts"][reviewer_id]["nonce"]) + 1,
        payload,
    )


def test_social_continuity_approve_schema_accepts_commitment_only_declaration() -> None:
    envelope, parsed = validate_tx_envelope(
        {
            "tx_type": "ACCOUNT_RECOVERY_APPROVE",
            "signer": "@reviewer01",
            "nonce": 1,
            "sig": "direct-test",
            "payload": {
                "request_id": "social-schema",
                "decision": "social_attest",
                "attestation_commitment": "sha256:" + "1" * 64,
                "household_commitment": "sha256:" + "2" * 64,
                "independence_commitment": "sha256:" + "3" * 64,
                "reason_code": "no_financial_or_institutional_dependency_v1",
            },
        }
    )
    assert envelope.tx_type == "ACCOUNT_RECOVERY_APPROVE"
    assert parsed is not None
    assert parsed.household_commitment == "sha256:" + "2" * 64


def test_continuity_evidence_rejects_unknown_classes_and_social_route_waits_for_attestors() -> None:
    state = _state(reviewer_count=20)
    state["accounts"]["@alice"] = _account("old-main")

    unknown = _continuity_payload("unknown-class", suffix="unknown")
    unknown["evidence_class_commitments"][0]["class_id"] = "invented_identity_oracle"
    unknown["recovery_evidence"][0]["class_id"] = "invented_identity_oracle"
    with pytest.raises(ApplyError) as invalid_class:
        _apply(state, "ACCOUNT_RECOVERY_REQUEST", "@alice", 1, unknown)
    assert invalid_class.value.reason == "unknown_continuity_evidence_class"

    state = _apply(
        state,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        1,
        _social_continuity_payload("social-pending"),
    )
    request = state["accounts"]["@alice"]["recovery"]["requests"]["social-pending"]
    assert request["status"] == "awaiting_social_attestations"
    assert request["social_attestation_minimum"] == 5
    assert schedule_account_recovery_system_txs(state, next_height=state["height"] + 1) == 0
    assert request["assigned_reviewers"] == []


def test_social_continuity_requires_signed_tier2_independent_households_before_assignment() -> None:
    state = _state(reviewer_count=20)
    state["accounts"]["@alice"] = _account("old-main")
    state["accounts"]["@tier0"] = _account("tier0-key", tier=0)
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        1,
        _social_continuity_payload("social-valid"),
    )

    with pytest.raises(ApplyError) as low_tier:
        _apply(
            state,
            "ACCOUNT_RECOVERY_APPROVE",
            "@tier0",
            1,
            {
                "request_id": "social-valid",
                "decision": "social_attest",
                "attestation_commitment": "sha256:" + "a" * 64,
                "household_commitment": "sha256:" + "b" * 64,
                "independence_commitment": "sha256:" + "c" * 64,
                "reason_code": "no_financial_or_institutional_dependency_v1",
            },
        )
    assert low_tier.value.reason == "social_continuity_attestor_requires_tier2"

    with pytest.raises(ApplyError) as missing_independence:
        _social_attest(state, "social-valid", 1, include_independence=False)
    assert missing_independence.value.reason == "social_continuity_commitments_required"

    with pytest.raises(ApplyError) as dependency_not_disclaimed:
        _social_attest(state, "social-valid", 1, reason_code="financial_dependency_present")
    assert (
        dependency_not_disclaimed.value.reason
        == "social_continuity_independence_declaration_required"
    )

    state = _social_attest(state, "social-valid", 1)
    with pytest.raises(ApplyError) as same_household:
        _social_attest(state, "social-valid", 2, household_index=101)
    assert same_household.value.reason == "social_continuity_households_not_distinct"

    for reviewer_index in range(2, 5):
        state = _social_attest(state, "social-valid", reviewer_index)
    request = state["accounts"]["@alice"]["recovery"]["requests"]["social-valid"]
    assert request["status"] == "awaiting_social_attestations"
    assert request["social_attestation_count"] == 4
    assert request["assigned_reviewers"] == []

    state = _social_attest(state, "social-valid", 5)
    request = state["accounts"]["@alice"]["recovery"]["requests"]["social-valid"]
    assert request["status"] == "awaiting_assignment"
    assert request["social_attestation_count"] == 5
    assert len(request["social_attestation_commitments"]) == 5
    assert (
        len({item["household_commitment"] for item in request["social_attestations"].values()}) == 5
    )
    assert all(
        "financial_dependency" not in item and "institutional_dependency" not in item
        for item in request["social_attestations"].values()
    )
    assert {item["class_id"] for item in request["evidence_class_commitments"]} == {
        "salted_credential_document_commitment",
        "social_continuity_attestations",
    }

    assert schedule_account_recovery_system_txs(state, next_height=state["height"] + 1) == 0
    assert request["status"] == "under_review"
    assert len(request["assigned_reviewers"]) == CONTINUITY_PANEL_SIZE


def test_social_continuity_attestation_window_expires_without_assignment() -> None:
    state = _state(reviewer_count=20)
    state["accounts"]["@alice"] = _account("old-main")
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        1,
        _social_continuity_payload("social-expired"),
    )
    request = state["accounts"]["@alice"]["recovery"]["requests"]["social-expired"]
    deadline = int(request["review_deadline_height"])
    assert schedule_account_recovery_system_txs(state, next_height=deadline + 1) == 1
    assert request["status"] == "expired"
    assert request["assigned_reviewers"] == []


def test_recovery_reversal_window_includes_final_restricted_height() -> None:
    def prepared(height: int, until: int) -> dict:
        state = _state(height=height, reviewer_count=30)
        state["accounts"]["@alice"] = _account("old-main")
        recovery = state["accounts"]["@alice"]["recovery"]
        recovery["restriction_until_height"] = until
        recovery["requests"]["prior-finalized"] = {
            "request_id": "prior-finalized",
            "status": "receipt_recorded",
            "assigned_reviewers": [],
        }
        return state

    before_boundary = prepared(499, 500)
    accepted_before = _apply(
        before_boundary,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        1,
        _continuity_payload(
            "reversal-before-boundary",
            method="reversal",
            challenged="prior-finalized",
            suffix="before-boundary",
        ),
    )
    assert (
        accepted_before["accounts"]["@alice"]["recovery"]["requests"]["reversal-before-boundary"][
            "status"
        ]
        == "awaiting_assignment"
    )

    at_boundary = prepared(500, 500)
    accepted = _apply(
        at_boundary,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        1,
        _continuity_payload(
            "reversal-at-boundary",
            method="reversal",
            challenged="prior-finalized",
            suffix="boundary",
        ),
    )
    assert accepted["accounts"]["@alice"]["recovery"]["requests"]["reversal-at-boundary"][
        "status"
    ] == ("awaiting_assignment")

    after_boundary = prepared(501, 500)
    with pytest.raises(ApplyError) as closed:
        _apply(
            after_boundary,
            "ACCOUNT_RECOVERY_REQUEST",
            "@alice",
            1,
            _continuity_payload(
                "reversal-after-boundary",
                method="reversal",
                challenged="prior-finalized",
                suffix="after-boundary",
            ),
        )
    assert closed.value.reason == "recovery_reversal_window_closed"


def test_continuity_recovery_and_fresh_panel_reversal_complete_atomically() -> None:
    state = _state(reviewer_count=45)
    state["accounts"]["@alice"] = _account("old-main")

    state = _apply(
        state,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        1,
        _continuity_payload("continuity-1", suffix="continuity"),
    )
    assert state["accounts"]["@alice"]["locked"] is True
    assert schedule_account_recovery_system_txs(state, next_height=101) == 0
    continuity = state["accounts"]["@alice"]["recovery"]["requests"]["continuity-1"]
    assert continuity["status"] == "under_review"
    assert len(continuity["assigned_reviewers"]) == CONTINUITY_PANEL_SIZE
    continuity_panel = set(continuity["assigned_reviewers"])

    state = _approve_recovery_panel(state, "continuity-1", CONTINUITY_APPROVAL_THRESHOLD)
    assert schedule_account_recovery_system_txs(state, next_height=102) == 1
    assert (
        state["accounts"]["@alice"]["recovery"]["requests"]["continuity-1"]["status"] == "approved"
    )
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_FINALIZE",
        "SYSTEM",
        0,
        {"request_id": "continuity-1"},
        system=True,
        parent="ACCOUNT_RECOVERY_APPROVE",
    )
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_RECEIPT",
        "SYSTEM",
        0,
        {"request_id": "continuity-1", "status": "finalized"},
        system=True,
        parent="ACCOUNT_RECOVERY_FINALIZE",
    )
    account = state["accounts"]["@alice"]
    assert account["active_keys"] == ["new-authority-continuity"]
    assert (
        account["recovery"]["restriction_until_height"]
        == state["height"] + RECOVERY_RESTRICTION_BLOCKS
    )
    assert account["recovery"]["history"][-1]["reviewer_ids"] == sorted(continuity_panel)
    for evidence_id in continuity["evidence_ids"]:
        record = evidence_record(state, evidence_id)
        assert record and record["state"] == "verification_closed"
        assert record["key_envelope_commitments"] == {}

    state["height"] += 1
    reversal_payload = _continuity_payload(
        "reversal-1",
        method="reversal",
        challenged="continuity-1",
        suffix="reversal",
    )
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        int(state["accounts"]["@alice"]["nonce"]) + 1,
        reversal_payload,
    )
    assert schedule_account_recovery_system_txs(state, next_height=state["height"] + 1) == 0
    reversal = state["accounts"]["@alice"]["recovery"]["requests"]["reversal-1"]
    reversal_panel = set(reversal["assigned_reviewers"])
    assert len(reversal_panel) == REVERSAL_PANEL_SIZE
    assert reversal_panel.isdisjoint(continuity_panel)

    state = _approve_recovery_panel(state, "reversal-1", REVERSAL_APPROVAL_THRESHOLD)
    assert schedule_account_recovery_system_txs(state, next_height=state["height"] + 2) == 1
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_FINALIZE",
        "SYSTEM",
        0,
        {"request_id": "reversal-1"},
        system=True,
        parent="ACCOUNT_RECOVERY_APPROVE",
    )
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_RECEIPT",
        "SYSTEM",
        0,
        {"request_id": "reversal-1", "status": "finalized"},
        system=True,
        parent="ACCOUNT_RECOVERY_FINALIZE",
    )
    account = state["accounts"]["@alice"]
    assert account["active_keys"] == ["new-authority-reversal"]
    assert account["recovery"]["offline_key"]["pubkey"] == "new-recovery-reversal"
    for evidence_id in reversal["evidence_ids"]:
        record = evidence_record(state, evidence_id)
        assert record and record["state"] == "verification_closed"
        assert record["key_envelope_commitments"] == {}
    assert any(item["request_id"] == "reversal-1" for item in state["account_recovery_incidents"])
    assert any(
        (
            rec.get("pubkey") == "new-authority-continuity"
            or (rec.get("pubkeys") or {}).get("mldsa") == "new-authority-continuity"
        )
        and rec.get("revoked") is True
        for rec in account["keys"]["by_id"].values()
    )


def test_prior_key_cannot_cancel_independent_recovery() -> None:
    state = _state()
    state["accounts"]["@alice"] = _account("main", recovery_pubkey="offline")
    state = _apply(
        state,
        "ACCOUNT_RECOVERY_REQUEST",
        "@alice",
        1,
        {
            "request_id": "offline-1",
            "target": "@alice",
            "method": "offline_key",
            "recovery_generation": 1,
            "new_pubkey": "replacement",
            "new_sig_profile": "pq-mldsa-v1",
            "new_recovery_pubkey": "replacement-recovery",
            "new_recovery_sig_profile": "pq-mldsa-v1",
        },
    )
    with pytest.raises(ApplyError) as cancelled:
        _apply(state, "ACCOUNT_RECOVERY_CANCEL", "@alice", 2, {"request_id": "offline-1"})
    assert cancelled.value.reason == "independent_recovery_not_cancellable"
    assert state["accounts"]["@alice"]["locked"] is True


def test_failed_recovery_attempts_are_canonical_and_rate_limited() -> None:
    state = _state(reviewer_count=5)
    state["accounts"]["@alice"] = _account("main")
    nonce = 1
    for attempt in range(3):
        request_id = f"failed-{attempt}"
        state = _apply(
            state,
            "ACCOUNT_RECOVERY_REQUEST",
            "@alice",
            nonce,
            _continuity_payload(request_id, suffix=str(attempt)),
        )
        schedule_account_recovery_system_txs(state, next_height=state["height"] + 1)
        request = state["accounts"]["@alice"]["recovery"]["requests"][request_id]
        assert request["status"] == "assignment_unavailable"
        state = _apply(
            state,
            "ACCOUNT_RECOVERY_RECEIPT",
            "SYSTEM",
            0,
            {"request_id": request_id, "status": "assignment_unavailable"},
            system=True,
            parent="ACCOUNT_RECOVERY_REQUEST",
        )
        nonce += 1
        if attempt < 2:
            state["height"] += RECOVERY_REQUEST_COOLDOWN_BLOCKS

    recovery = state["accounts"]["@alice"]["recovery"]
    assert len(recovery["failed_attempt_heights"]) == 3
    assert all(
        state["height"] - h <= RECOVERY_FAILED_WINDOW_BLOCKS
        for h in recovery["failed_attempt_heights"]
    )
    state["height"] += RECOVERY_REQUEST_COOLDOWN_BLOCKS
    with pytest.raises(ApplyError) as blocked:
        _apply(
            state,
            "ACCOUNT_RECOVERY_REQUEST",
            "@alice",
            nonce,
            _continuity_payload("failed-3", suffix="3"),
        )
    assert blocked.value.reason == "recovery_failed_attempt_limit"


def test_encrypted_evidence_closes_revokes_access_retries_and_erases() -> None:
    state = _state(height=20)
    register_encrypted_evidence(
        state,
        case_id="case:1",
        evidence_id="evidence:1",
        subject_id="@alice",
        ciphertext_cid="bafy-ciphertext",
        ciphertext_commitment="sha256:" + "1" * 64,
        encryption_context_commitment="sha256:" + "2" * 64,
        provider_ids=["@provider1", "@provider2"],
        declared_height=20,
    )
    mark_reviewer_accessible(
        state,
        evidence_id="evidence:1",
        key_envelope_commitments=_envelopes(["@alice", "@reviewer01"]),
        required_principals={"@alice", "@reviewer01"},
        height=21,
    )
    rec = evidence_record(state, "evidence:1")
    assert rec and rec["state"] == "reviewer_accessible"

    assert close_case_evidence(state, case_id="case:1", finalized_height=30) == ["evidence:1"]
    rec = evidence_record(state, "evidence:1")
    assert rec and rec["state"] == "verification_closed"
    assert rec["key_envelope_commitments"] == {}
    assert rec["deletion_due_height"] == 30 + EVIDENCE_RETENTION_BLOCKS

    assert process_evidence_lifecycle(state, next_height=31) == 1
    assert evidence_record(state, "evidence:1")["state"] == "sealed_retention"

    due = rec["deletion_due_height"]
    assert process_evidence_lifecycle(state, next_height=due) == 1
    rec = evidence_record(state, "evidence:1")
    assert rec and rec["state"] == "deletion_due"
    assert rec["failure_count"] == 0
    assert process_evidence_lifecycle(state, next_height=due + 1) == 1
    assert rec["state"] == "deletion_due"
    assert rec["failure_count"] == 1

    record_provider_deletion_attestation(
        state,
        evidence_id="evidence:1",
        provider_id="@provider1",
        storage_commitment="sha256:" + "3" * 64,
        key_erasure_commitment="sha256:" + "4" * 64,
        attestation_commitment="sha256:" + "5" * 64,
        height=due + 10,
    )
    retry_height = due + 1 + EVIDENCE_DELETE_RETRY_BLOCKS
    assert process_evidence_lifecycle(state, next_height=retry_height) == 1
    assert evidence_record(state, "evidence:1")["failure_count"] == 2

    record_provider_deletion_attestation(
        state,
        evidence_id="evidence:1",
        provider_id="@provider2",
        storage_commitment="sha256:" + "6" * 64,
        key_erasure_commitment="sha256:" + "7" * 64,
        attestation_commitment="sha256:" + "8" * 64,
        height=retry_height + 1,
    )
    assert process_evidence_lifecycle(state, next_height=retry_height + 1) == 1
    rec = evidence_record(state, "evidence:1")
    assert rec and rec["state"] == "erased"
    assert process_evidence_lifecycle(state, next_height=retry_height + 2) == 1
    assert rec["state"] == "deletion_receipt"
    receipt = state["poh"]["evidence_lifecycle"]["receipts"][-1]
    assert receipt["status"] == "erased"
    assert set(receipt["provider_attestations"]) == {"@provider1", "@provider2"}


def test_evidence_deletion_deadline_miss_is_public_and_retries_continue() -> None:
    state = _state(height=1)
    register_encrypted_evidence(
        state,
        case_id="case:deadline",
        evidence_id="evidence:deadline",
        subject_id="@alice",
        ciphertext_cid="bafy-deadline",
        ciphertext_commitment="sha256:" + "1" * 64,
        encryption_context_commitment="sha256:" + "2" * 64,
        provider_ids=["@provider1"],
        declared_height=1,
    )
    mark_reviewer_accessible(
        state,
        evidence_id="evidence:deadline",
        key_envelope_commitments=_envelopes(["@alice"]),
        required_principals={"@alice"},
        height=2,
    )
    close_case_evidence(state, case_id="case:deadline", finalized_height=10)
    rec = evidence_record(state, "evidence:deadline")
    assert rec is not None
    due = int(rec["deletion_due_height"])
    deadline = due + EVIDENCE_DELETE_COMPLETION_BLOCKS
    assert process_evidence_lifecycle(state, next_height=11) == 1
    assert process_evidence_lifecycle(state, next_height=due) == 1
    rec["next_retry_height"] = deadline
    transitions = process_evidence_lifecycle(state, next_height=deadline)
    assert transitions == 2
    assert rec["deletion_deadline_missed_height"] == deadline
    receipts = state["poh"]["evidence_lifecycle"]["receipts"]
    assert any(item["status"] == "deletion_deadline_missed" for item in receipts)
    assert rec["state"] == "deletion_due"
    assert rec["next_retry_height"] == deadline + EVIDENCE_DELETE_RETRY_BLOCKS


def test_plaintext_poh_evidence_is_rejected_and_async_decline_is_replaced() -> None:
    state = _state(reviewer_count=4)
    state["accounts"]["@alice"] = _account("alice-main")
    with pytest.raises(ApplyError) as plaintext:
        _apply(
            state,
            "POH_ASYNC_EVIDENCE_DECLARE",
            "@alice",
            1,
            {"case_id": "missing", "evidence_id": "plaintext", "cid": "bafy-plaintext"},
        )
    # The case lookup may fail first for a fabricated case, so exercise the
    # generic evidence path as the explicit plaintext bypass guard.
    assert plaintext.value.reason in {
        "unknown_async_case",
        "async_case_not_found",
        "plaintext_poh_evidence_forbidden",
    }
    with pytest.raises(ApplyError) as generic_plaintext:
        _apply(
            state,
            "POH_EVIDENCE_DECLARE",
            "@alice",
            1,
            {"evidence_id": "plaintext", "cid": "bafy-plaintext"},
        )
    assert generic_plaintext.value.reason == "plaintext_poh_evidence_forbidden"

    state = _apply(
        state,
        "POH_ASYNC_REQUEST_OPEN",
        "@alice",
        1,
        {
            "account_id": "@alice",
            "case_id": "case:async:replace",
            "challenge_id": "challenge:1",
            "challenge_commitment": "sha256:" + "a" * 64,
        },
    )
    state = _apply(
        state,
        "POH_ASYNC_EVIDENCE_DECLARE",
        "@alice",
        2,
        _encrypted_declare_payload("case:async:replace", "evidence:replace"),
    )
    state = _apply(
        state,
        "POH_ASYNC_EVIDENCE_BIND",
        "@alice",
        3,
        {
            "case_id": "case:async:replace",
            "evidence_id": "evidence:replace",
            "target_id": "case:async:replace",
            "evidence_root_commitment": "sha256:" + "b" * 64,
            "key_envelope_commitments": _envelopes(["@alice"]),
        },
    )
    assert schedule_poh_async_system_txs(state, next_height=101) == 1
    assignment = next(
        item for item in state["system_queue"] if item["tx_type"] == "POH_ASYNC_JUROR_ASSIGN"
    )
    state = _apply(
        state,
        "POH_ASYNC_JUROR_ASSIGN",
        "SYSTEM",
        0,
        assignment["payload"],
        system=True,
        parent="POH_ASYNC_REQUEST_OPEN",
    )
    original = list(state["poh"]["async_cases"]["case:async:replace"]["assigned_jurors"])
    state = _apply(
        state,
        "POH_ASYNC_EVIDENCE_BIND",
        "@alice",
        4,
        {
            "case_id": "case:async:replace",
            "evidence_id": "evidence:replace",
            "target_id": "case:async:replace",
            "evidence_root_commitment": "sha256:" + "b" * 64,
            "key_envelope_commitments": _envelopes(["@alice", *original]),
        },
    )
    declined = original[0]
    state = _apply(state, "POH_ASYNC_JUROR_DECLINE", declined, 1, {"case_id": "case:async:replace"})
    state["system_queue"] = []
    assert schedule_poh_async_system_txs(state, next_height=102) == 1
    replacement_assignment = next(
        item for item in state["system_queue"] if item["tx_type"] == "POH_ASYNC_JUROR_ASSIGN"
    )
    state = _apply(
        state,
        "POH_ASYNC_JUROR_ASSIGN",
        "SYSTEM",
        0,
        replacement_assignment["payload"],
        system=True,
        parent="POH_ASYNC_JUROR_DECLINE",
    )
    current = list(state["poh"]["async_cases"]["case:async:replace"]["assigned_jurors"])
    assert declined not in current
    replacement = next(value for value in current if value not in original)
    with pytest.raises(ApplyError) as no_envelope:
        _apply(state, "POH_ASYNC_JUROR_ACCEPT", replacement, 1, {"case_id": "case:async:replace"})
    assert no_envelope.value.reason == "async_reviewer_key_envelope_required"

    state = _apply(
        state,
        "POH_ASYNC_EVIDENCE_BIND",
        "@alice",
        4,
        {
            "case_id": "case:async:replace",
            "evidence_id": "evidence:replace",
            "target_id": "case:async:replace",
            "evidence_root_commitment": "sha256:" + "b" * 64,
            "key_envelope_commitments": _envelopes(["@alice", *current]),
        },
    )
    state = _apply(
        state, "POH_ASYNC_JUROR_ACCEPT", replacement, 1, {"case_id": "case:async:replace"}
    )
    assert replacement in state["poh"]["async_cases"]["case:async:replace"]["accepted_jurors"]


def test_tier2_reverification_case_and_responsibility_transition_are_canonical() -> None:
    state = _state(height=0)
    state["accounts"]["@alice"] = _account("main", tier=2)
    state["roles"]["jurors"]["by_id"] = {
        "@alice": {
            "account_id": "@alice",
            "status": "active",
            "active": True,
            "responsibilities": {
                "reviewer": {"poh_async_review": {"opted_in": True, "active": True}}
            },
        }
    }
    verified = 10
    fields = tier2_lifecycle_fields(verified)
    set_account_poh_status(
        state,
        account_id="@alice",
        poh_tier=2,
        status=POH_STATUS_ACTIVE,
        verified_at_height=verified,
        expires_at_height=fields["expires_at_height"],
        last_updated_height=verified,
    )
    open_height = fields["expires_at_height"] - TIER2_REMINDER_OFFSETS[0]
    result = process_tier2_lifecycle(state, next_height=open_height)
    assert result["reverification_opened"] == 1
    case_id = state["poh"]["tier2_lifecycle"]["by_account"]["@alice"]["reverification_case_id"]
    live_case = state["poh"]["live_cases"][case_id]
    assert live_case["reverification"] is True
    assert live_case["relay_authority"] == "transport_only"

    expiry_result = process_tier2_lifecycle(state, next_height=fields["expires_at_height"] + 1)
    assert expiry_result["expired"] == 1
    role = state["roles"]["jurors"]["by_id"]["@alice"]
    assert role["status"] == "replacement_required"
    assert role["no_new_assignments"] is True
    assert (
        role["safe_withdrawal_until_height"]
        == fields["expires_at_height"] + 1 + SAFE_WITHDRAWAL_BLOCKS
    )
    elapsed = process_tier2_lifecycle(
        state,
        next_height=role["safe_withdrawal_until_height"] + 1,
    )
    assert elapsed["safe_withdrawals"] == 1


def test_account_tier_gates_and_pinned_genesis_recovery_policy_match_m2() -> None:
    canon = load_default_tx_index()
    assert canon.get("CONTENT_COMMENT_CREATE")["subject_gate"] == "Tier0+"
    assert canon.get("CONTENT_FLAG")["subject_gate"] == "Tier1+"
    assert canon.get("DISPUTE_OPEN")["subject_gate"] == "Tier1+"

    root = Path(__file__).resolve().parents[1]
    for name in ("genesis.ledger.prod.json", "genesis.ledger.testnet-v1.json"):
        data = json.loads((root / "configs" / name).read_text(encoding="utf-8"))
        params = data["params"]
        assert params["guardian_recovery_new_admission"] is False
        assert params["require_recovery_key_at_account_register"] is True
        assert params["require_evidence_kem_at_account_register"] is True


def test_recovery_rejects_reused_or_nonindependent_replacement_keys() -> None:
    state = _state()
    state["accounts"]["@alice"] = _account("old-main", recovery_pubkey="offline-current")
    state["accounts"]["@alice"]["recovery"]["prior_offline_keys"] = [
        {"pubkey": "offline-retired", "sig_profile": "pq-mldsa-v1", "generation": 0}
    ]

    base = {
        "request_id": "freshness-check",
        "target": "@alice",
        "method": "offline_key",
        "recovery_generation": 1,
        "new_sig_profile": "pq-mldsa-v1",
        "new_recovery_sig_profile": "pq-mldsa-v1",
    }
    with pytest.raises(ApplyError) as reused_active:
        _apply(
            state,
            "ACCOUNT_RECOVERY_REQUEST",
            "@alice",
            1,
            {**base, "new_pubkey": "old-main", "new_recovery_pubkey": "offline-new"},
        )
    assert reused_active.value.reason == "recovered_authority_key_must_be_fresh"

    with pytest.raises(ApplyError) as shared_key:
        _apply(
            state,
            "ACCOUNT_RECOVERY_REQUEST",
            "@alice",
            1,
            {**base, "new_pubkey": "new-shared", "new_recovery_pubkey": "new-shared"},
        )
    assert shared_key.value.reason == "recovery_key_must_be_independent"

    with pytest.raises(ApplyError) as reused_recovery:
        _apply(
            state,
            "ACCOUNT_RECOVERY_REQUEST",
            "@alice",
            1,
            {**base, "new_pubkey": "new-authority", "new_recovery_pubkey": "offline-retired"},
        )
    assert reused_recovery.value.reason == "recovery_key_must_be_fresh"
