from __future__ import annotations

"""Canonical lifecycle for encrypted Proof-of-Humanity evidence.

Raw identity media is never valid consensus payload.  Consensus stores only
ciphertext object identifiers, commitments, recipient-envelope commitments, and
provider deletion attestations.  The module intentionally has no provider or
filesystem I/O; operators execute deletion off-chain and attest the result with
signed protocol transactions.
"""

import hashlib
from typing import Any

Json = dict[str, Any]

EVIDENCE_POLICY_VERSION = "poh-encrypted-evidence-v1"
EVIDENCE_RETENTION_BLOCKS = 129_600
EVIDENCE_DELETE_COMPLETION_BLOCKS = 4_320
EVIDENCE_DELETE_RETRY_BLOCKS = 180

EVIDENCE_STATE_UPLOADED = "uploaded"
EVIDENCE_STATE_REVIEWER_ACCESSIBLE = "reviewer_accessible"
EVIDENCE_STATE_VERIFICATION_CLOSED = "verification_closed"
EVIDENCE_STATE_SEALED_RETENTION = "sealed_retention"
EVIDENCE_STATE_DELETION_DUE = "deletion_due"
EVIDENCE_STATE_ERASED = "erased"
EVIDENCE_STATE_DELETION_RECEIPT = "deletion_receipt"


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _root(state: Json) -> Json:
    poh = state.setdefault("poh", {})
    lifecycle = poh.setdefault("evidence_lifecycle", {})
    lifecycle.setdefault("by_evidence", {})
    lifecycle.setdefault("receipts", [])
    return lifecycle


def evidence_record(state: Json, evidence_id: str) -> Json | None:
    rec = _root(state).get("by_evidence", {}).get(_as_str(evidence_id))
    return rec if isinstance(rec, dict) else None


def register_encrypted_evidence(
    state: Json,
    *,
    case_id: str,
    evidence_id: str,
    subject_id: str,
    ciphertext_cid: str,
    ciphertext_commitment: str,
    encryption_context_commitment: str,
    provider_ids: list[str],
    declared_height: int,
) -> Json:
    lifecycle = _root(state)
    records = lifecycle["by_evidence"]
    evidence_id = _as_str(evidence_id)
    if evidence_id in records:
        raise ValueError("evidence_lifecycle_exists")
    providers = sorted({_as_str(value) for value in provider_ids if _as_str(value)})
    if not providers:
        raise ValueError("missing_evidence_provider_ids")
    rec: Json = {
        "evidence_id": evidence_id,
        "case_id": _as_str(case_id),
        "subject_id": _as_str(subject_id),
        "policy_version": EVIDENCE_POLICY_VERSION,
        "state": EVIDENCE_STATE_UPLOADED,
        "encryption_algorithm": "aes-256-gcm",
        "ciphertext_cid": _as_str(ciphertext_cid),
        "ciphertext_commitment": _as_str(ciphertext_commitment),
        "encryption_context_commitment": _as_str(encryption_context_commitment),
        "provider_ids": providers,
        "declared_height": int(declared_height),
        "key_envelope_commitments": {},
        "provider_attestations": {},
        "failure_count": 0,
    }
    records[evidence_id] = rec
    return rec


def mark_reviewer_accessible(
    state: Json,
    *,
    evidence_id: str,
    key_envelope_commitments: Json,
    required_principals: set[str],
    height: int,
) -> Json:
    rec = evidence_record(state, evidence_id)
    if rec is None:
        raise ValueError("unknown_evidence_lifecycle")
    envelopes = {
        _as_str(principal): value
        for principal, value in key_envelope_commitments.items()
        if _as_str(principal) and value is not None
    }
    missing = sorted(principal for principal in required_principals if principal not in envelopes)
    if missing:
        raise ValueError(f"missing_key_envelopes:{','.join(missing)}")
    rec["key_envelope_commitments"] = envelopes
    rec["state"] = EVIDENCE_STATE_REVIEWER_ACCESSIBLE
    rec["reviewer_accessible_height"] = int(height)
    return rec


def close_case_evidence(state: Json, *, case_id: str, finalized_height: int) -> list[str]:
    """Revoke reviewer access and enter the explicit verification-closed state.

    The next deterministic lifecycle tick advances the record into sealed
    retention.  Keeping this boundary explicit makes POH-301 observable rather
    than collapsing verification closure and retention into one mutation.
    """

    lifecycle = _root(state)
    closed: list[str] = []
    for evidence_id, rec_any in sorted(lifecycle["by_evidence"].items()):
        rec = rec_any if isinstance(rec_any, dict) else None
        if rec is None or _as_str(rec.get("case_id")) != _as_str(case_id):
            continue
        if _as_str(rec.get("state")) in {
            EVIDENCE_STATE_ERASED,
            EVIDENCE_STATE_DELETION_RECEIPT,
        }:
            continue
        rec["state"] = EVIDENCE_STATE_VERIFICATION_CLOSED
        rec["verification_closed_height"] = int(finalized_height)
        rec["access_grants_revoked_height"] = int(finalized_height)
        rec["key_envelope_commitments"] = {}
        rec["deletion_due_height"] = int(finalized_height) + EVIDENCE_RETENTION_BLOCKS
        rec["deletion_completion_deadline_height"] = (
            rec["deletion_due_height"] + EVIDENCE_DELETE_COMPLETION_BLOCKS
        )
        closed.append(evidence_id)
    return closed


def record_provider_deletion_attestation(
    state: Json,
    *,
    evidence_id: str,
    provider_id: str,
    storage_commitment: str,
    key_erasure_commitment: str,
    attestation_commitment: str,
    height: int,
) -> Json:
    rec = evidence_record(state, evidence_id)
    if rec is None:
        raise ValueError("unknown_evidence_lifecycle")
    provider_id = _as_str(provider_id)
    if provider_id not in set(rec.get("provider_ids", [])):
        raise ValueError("provider_not_recorded_for_evidence")
    attestations = rec.setdefault("provider_attestations", {})
    attestations[provider_id] = {
        "provider_id": provider_id,
        "storage_commitment": _as_str(storage_commitment),
        "key_erasure_commitment": _as_str(key_erasure_commitment),
        "attestation_commitment": _as_str(attestation_commitment),
        "height": int(height),
    }
    return rec


def _receipt_id(evidence_id: str, status: str, height: int, failure_count: int) -> str:
    digest = hashlib.sha256(
        f"POH_EVIDENCE_DELETION_V1|{evidence_id}|{status}|{height}|{failure_count}".encode("utf-8")
    ).hexdigest()
    return f"poh-evidence-deletion:{digest[:32]}"


def _append_deletion_receipt(lifecycle: Json, rec: Json, *, evidence_id: str, height: int) -> str:
    receipts = lifecycle["receipts"]
    existing = _as_str(rec.get("deletion_receipt_id"))
    if existing and any(isinstance(item, dict) and item.get("receipt_id") == existing for item in receipts):
        rec.setdefault("deletion_receipt_height", int(height))
        return existing
    rid = existing or _receipt_id(
        evidence_id, "erased", int(height), _as_int(rec.get("failure_count"), 0)
    )
    if not any(isinstance(item, dict) and item.get("receipt_id") == rid for item in receipts):
        providers = set(rec.get("provider_ids", []))
        attestations = rec.get("provider_attestations")
        attestations = attestations if isinstance(attestations, dict) else {}
        receipts.append(
            {
                "receipt_id": rid,
                "evidence_id": evidence_id,
                "case_id": rec.get("case_id"),
                "policy_version": rec.get("policy_version"),
                "status": "erased",
                "height": int(height),
                "ciphertext_commitment": rec.get("ciphertext_commitment"),
                "encryption_context_commitment": rec.get("encryption_context_commitment"),
                "provider_attestations": {
                    provider: attestations[provider] for provider in sorted(providers)
                },
                "failure_count": _as_int(rec.get("failure_count"), 0),
                "deletion_due_height": rec.get("deletion_due_height"),
                "deletion_completion_deadline_height": rec.get("deletion_completion_deadline_height"),
                "deletion_deadline_missed_height": rec.get("deletion_deadline_missed_height"),
            }
        )
    rec["deletion_receipt_id"] = rid
    rec["deletion_receipt_height"] = int(height)
    return rid


def process_evidence_lifecycle(state: Json, *, next_height: int) -> int:
    """Advance each evidence item by at most one canonical POH-301 state.

    Legacy ``erasure_pending`` records are deterministically migrated to
    ``deletion_due``.  Failed deletion attempts remain in deletion-due state,
    emit public failure receipts, and retry on the 180-block cadence required by
    POH-304.
    """

    lifecycle = _root(state)
    receipts = lifecycle["receipts"]
    transitions = 0
    for evidence_id, rec_any in sorted(lifecycle["by_evidence"].items()):
        rec = rec_any if isinstance(rec_any, dict) else None
        if rec is None:
            continue
        status = _as_str(rec.get("state"))
        due = _as_int(rec.get("deletion_due_height"), 0)

        if status == EVIDENCE_STATE_VERIFICATION_CLOSED:
            rec["state"] = EVIDENCE_STATE_SEALED_RETENTION
            rec["sealed_retention_height"] = int(next_height)
            transitions += 1
            continue

        if status == EVIDENCE_STATE_SEALED_RETENTION and due and int(next_height) >= due:
            rec["state"] = EVIDENCE_STATE_DELETION_DUE
            rec["deletion_due_reached_height"] = int(next_height)
            rec["next_retry_height"] = max(due, int(next_height))
            transitions += 1
            continue

        # Deterministic migration of the pre-POH-301 name.
        if status == "erasure_pending":
            rec["state"] = EVIDENCE_STATE_DELETION_DUE
            rec.setdefault("deletion_due_reached_height", _as_int(rec.get("erasure_pending_height"), int(next_height)))
            rec.setdefault("next_retry_height", max(due, int(next_height)))
            transitions += 1
            continue

        if status == EVIDENCE_STATE_ERASED:
            _append_deletion_receipt(lifecycle, rec, evidence_id=evidence_id, height=int(next_height))
            rec["state"] = EVIDENCE_STATE_DELETION_RECEIPT
            transitions += 1
            continue

        if status != EVIDENCE_STATE_DELETION_DUE:
            continue

        providers = set(rec.get("provider_ids", []))
        attestations = rec.get("provider_attestations")
        attestations = attestations if isinstance(attestations, dict) else {}
        if providers and providers.issubset(set(attestations.keys())):
            rec["state"] = EVIDENCE_STATE_ERASED
            rec["erased_height"] = int(next_height)
            transitions += 1
            continue

        missing = sorted(providers.difference(attestations.keys()))
        deadline = _as_int(rec.get("deletion_completion_deadline_height"), 0)
        if deadline and int(next_height) >= deadline and not rec.get("deletion_deadline_missed_height"):
            rec["deletion_deadline_missed_height"] = int(next_height)
            rid = _receipt_id(
                evidence_id,
                "deletion_deadline_missed",
                int(next_height),
                _as_int(rec.get("failure_count"), 0),
            )
            receipts.append(
                {
                    "receipt_id": rid,
                    "evidence_id": evidence_id,
                    "case_id": rec.get("case_id"),
                    "policy_version": rec.get("policy_version"),
                    "status": "deletion_deadline_missed",
                    "height": int(next_height),
                    "deadline_height": deadline,
                    "missing_provider_ids": missing,
                    "failure_count": _as_int(rec.get("failure_count"), 0),
                }
            )
            transitions += 1

        retry_at = _as_int(rec.get("next_retry_height"), due)
        if int(next_height) < retry_at:
            continue
        failure_count = _as_int(rec.get("failure_count"), 0) + 1
        rec["failure_count"] = failure_count
        rec["last_failure_height"] = int(next_height)
        rec["next_retry_height"] = int(next_height) + EVIDENCE_DELETE_RETRY_BLOCKS
        rid = _receipt_id(evidence_id, "deletion_pending", int(next_height), failure_count)
        receipts.append(
            {
                "receipt_id": rid,
                "evidence_id": evidence_id,
                "case_id": rec.get("case_id"),
                "policy_version": rec.get("policy_version"),
                "status": "deletion_pending",
                "height": int(next_height),
                "missing_provider_ids": missing,
                "failure_count": failure_count,
                "next_retry_height": rec["next_retry_height"],
            }
        )
        transitions += 1
    return transitions



__all__ = [
    "EVIDENCE_DELETE_COMPLETION_BLOCKS",
    "EVIDENCE_DELETE_RETRY_BLOCKS",
    "EVIDENCE_POLICY_VERSION",
    "EVIDENCE_RETENTION_BLOCKS",
    "EVIDENCE_STATE_DELETION_DUE",
    "EVIDENCE_STATE_DELETION_RECEIPT",
    "EVIDENCE_STATE_ERASED",
    "EVIDENCE_STATE_REVIEWER_ACCESSIBLE",
    "EVIDENCE_STATE_SEALED_RETENTION",
    "EVIDENCE_STATE_UPLOADED",
    "EVIDENCE_STATE_VERIFICATION_CLOSED",
    "close_case_evidence",
    "evidence_record",
    "mark_reviewer_accessible",
    "process_evidence_lifecycle",
    "record_provider_deletion_attestation",
    "register_encrypted_evidence",
]
