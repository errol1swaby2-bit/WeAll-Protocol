"""Reference-only cryptographic preflight for genesis independence-review records.

BSTR-032 requires household, funding, key-custody and infrastructure review.
Signing a review does not establish actual independence or constitutional
authority. This module is NOT imported into production consensus, the
executor, block builder, replay, or SYSTEM scheduler.

All expected roster digests must come from independently trusted channels;
a digest computed by the candidate's own sender is not a trust root.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from weall.crypto.pq_mldsa import MLDSA65_PUBLIC_KEY_BYTES, MLDSA65_SIGNATURE_BYTES
from weall.crypto.sig import verify_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1, profile_allowed_for_context
from weall.runtime.commitments import canonical_json_sha256
from weall.runtime.genesis_acceptance_witness import (
    GenesisAcceptancePreflightError,
    GenesisManifestBindingEvidence,
    GenesisWitnessRosterEvidence,
    INDEPENDENCE_DOMAINS,
    _hex_bytes,
    _ident,
    _sha256,
)

Json = dict[str, Any]
REVIEWER_ROSTER_SCHEMA = "weall.genesis-independence-reviewer-roster.preflight.v1"
SIGNED_REVIEW_SCHEMA = "weall.genesis-independence-review.preflight.v1"
REVIEW_SIGNATURE_DOMAIN = b"weall.genesis-independence-review.preflight.v1\x00"
REVIEW_FINDINGS = frozenset({"no_conflict_found", "conflict_found", "insufficient_evidence"})
REVIEW_CONFLICT_DECLARATIONS = frozenset({"none_declared", "conflict_declared", "unknown"})


@dataclass(frozen=True, slots=True)
class GenesisIndependenceReviewPreflightEvidence:
    """Signed statements verified; absolutely no independence or launch approval."""

    chain_id: str
    genesis_manifest_sha256: str
    ceremony_id: str
    witness_roster_sha256: str
    reviewer_roster_sha256: str
    signed_reviewer_ids: tuple[str, ...]
    reviewed_witness_ids: tuple[str, ...]
    verified_domain_statements: int
    unresolved_domain_statements: int
    conflicted_or_unknown_reviewer_ids: tuple[str, ...]
    evidence_status: str = "signed_review_provenance_only"
    real_world_independence_verified: bool = False
    constitutional_approval_recorded: bool = False
    authorizes_first_finality: bool = False


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise GenesisAcceptancePreflightError(reason)


def genesis_review_signing_message(statement: Json) -> bytes:
    """Domain-separated candidate review message, NOT a ratified wire format."""
    payload = {key: val for key, val in statement.items() if key != "signature"}
    return REVIEW_SIGNATURE_DOMAIN + json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def preflight_signed_genesis_independence_reviews(
    *,
    reviewer_roster: Json,
    expected_reviewer_roster_sha256: str,
    signed_reviews: list[Json],
    genesis_binding: GenesisManifestBindingEvidence,
    witness_roster_binding: GenesisWitnessRosterEvidence,
    witness_roster: Json,
    genesis_validator_pubkey: str,
) -> GenesisIndependenceReviewPreflightEvidence:
    """Verify signed, externally pinned *review evidence*, never acceptance.

    A reviewer's signature and a separate trusted reviewer-roster hash bind the
    recorded claims to signing keys, not to verified independent persons or to
    a constitutionally approved registrar. Every pinned reviewer must submit
    one signature covering every pinned witness and all four review domains.
    A signed conflict/unknown finding is preserved, not silently upgraded.
    """
    _require(isinstance(reviewer_roster, dict), "reviewer_roster_not_object")
    _require(
        set(reviewer_roster)
        == {
            "schema",
            "chain_id",
            "genesis_manifest_sha256",
            "ceremony_id",
            "witness_roster_sha256",
            "reviewers",
        },
        "reviewer_roster_fields_invalid",
    )
    _require(
        reviewer_roster["schema"] == REVIEWER_ROSTER_SCHEMA,
        "reviewer_roster_schema_invalid",
    )
    _require(_sha256(expected_reviewer_roster_sha256), "trusted_reviewer_digest_invalid")
    try:
        roster_digest = canonical_json_sha256(reviewer_roster)
    except (ValueError, TypeError, OverflowError) as exc:
        raise GenesisAcceptancePreflightError("reviewer_roster_noncanonical_json") from exc
    _require(roster_digest == expected_reviewer_roster_sha256, "reviewer_roster_anchor_mismatch")
    _require(
        reviewer_roster["chain_id"] == genesis_binding.chain_id
        == witness_roster_binding.chain_id,
        "reviewer_roster_chain_mismatch",
    )
    _require(
        reviewer_roster["genesis_manifest_sha256"]
        == genesis_binding.genesis_manifest_sha256
        == witness_roster_binding.genesis_manifest_sha256,
        "reviewer_roster_manifest_mismatch",
    )
    _require(
        reviewer_roster["ceremony_id"]
        == witness_roster_binding.ceremony_id
        == genesis_binding.witness_signatures.ceremony_id,
        "reviewer_roster_ceremony_mismatch",
    )
    _require(
        reviewer_roster["witness_roster_sha256"]
        == witness_roster_binding.externally_pinned_roster_sha256,
        "reviewer_roster_witness_binding_mismatch",
    )
    _require(
        _hex_bytes(genesis_validator_pubkey, MLDSA65_PUBLIC_KEY_BYTES)
        and hashlib.sha256(bytes.fromhex(genesis_validator_pubkey)).hexdigest()
        == genesis_binding.genesis_validator_pubkey_sha256,
        "reviewer_genesis_key_mismatch",
    )
    witness_entries = witness_roster.get("witnesses")
    _require(isinstance(witness_entries, list), "reviewer_witness_roster_missing")
    witness_keys: set[str] = set()
    witnessed_ids: set[str] = set()
    for item in witness_entries:
        _require(
            isinstance(item, dict) and set(item) == {"witness_id", "pubkey"},
            "reviewer_witness_entry_invalid",
        )
        _require(
            _ident(item["witness_id"])
            and _hex_bytes(item["pubkey"], MLDSA65_PUBLIC_KEY_BYTES),
            "reviewer_witness_identity_invalid",
        )
        _require(
            item["witness_id"] not in witnessed_ids and item["pubkey"] not in witness_keys,
            "reviewer_witness_duplicate",
        )
        witnessed_ids.add(item["witness_id"])
        witness_keys.add(item["pubkey"])
    _require(
        canonical_json_sha256(witness_roster)
        == witness_roster_binding.externally_pinned_roster_sha256
        and tuple(sorted(witnessed_ids)) == witness_roster_binding.witness_ids,
        "reviewer_witness_roster_digest_mismatch",
    )

    entries = reviewer_roster["reviewers"]
    _require(isinstance(entries, list) and len(entries) >= 2, "reviewer_roster_too_small")
    reviewer_keys: dict[str, str] = {}
    seen_keys: set[str] = set()
    for item in entries:
        _require(
            isinstance(item, dict) and set(item) == {"reviewer_id", "pubkey"},
            "reviewer_roster_entry_invalid",
        )
        identity = item["reviewer_id"]
        key = item["pubkey"]
        _require(_ident(identity), "reviewer_identity_invalid")
        _require(_hex_bytes(key, MLDSA65_PUBLIC_KEY_BYTES), "reviewer_public_key_invalid")
        _require(identity not in reviewer_keys, "duplicate_reviewer_identity")
        _require(key not in seen_keys, "duplicate_reviewer_public_key")
        _require(key != genesis_validator_pubkey and key not in witness_keys, "reviewer_key_role_reuse")
        reviewer_keys[identity] = key
        seen_keys.add(key)

    _require(isinstance(signed_reviews, list), "review_statements_not_list")
    _require(len(signed_reviews) == len(reviewer_keys), "review_signer_count_mismatch")
    available, _reason = profile_allowed_for_context(
        PQ_MLDSA_V1, purpose="signing", require_verifier=True
    )
    _require(available, "review_signature_profile_unavailable")
    signed_ids: set[str] = set()
    unresolved_count = 0
    conflict_ids: set[str] = set()
    for statement in signed_reviews:
        _require(isinstance(statement, dict), "signed_review_not_object")
        _require(
            set(statement)
            == {
                "schema", "chain_id", "genesis_manifest_sha256",
                "ceremony_id", "witness_roster_sha256", "reviewer_roster_sha256",
                "reviewer_id", "pubkey", "sig_profile", "conflict_of_interest",
                "assessments", "signature",
            },
            "signed_review_fields_invalid",
        )
        _require(statement["schema"] == SIGNED_REVIEW_SCHEMA, "signed_review_schema_invalid")
        reviewer_id = statement["reviewer_id"]
        _require(
            isinstance(reviewer_id, str) and reviewer_id in reviewer_keys,
            "unapproved_review_signer",
        )
        _require(reviewer_id not in signed_ids, "duplicate_signed_review")
        signed_ids.add(reviewer_id)
        _require(
            statement["pubkey"] == reviewer_keys[reviewer_id],
            "reviewer_public_key_mismatch",
        )
        _require(statement["sig_profile"] == PQ_MLDSA_V1, "review_signature_profile_invalid")
        _require(
            statement["chain_id"] == genesis_binding.chain_id
            and statement["genesis_manifest_sha256"] == genesis_binding.genesis_manifest_sha256
            and statement["ceremony_id"] == witness_roster_binding.ceremony_id
            and statement["witness_roster_sha256"]
            == witness_roster_binding.externally_pinned_roster_sha256
            and statement["reviewer_roster_sha256"] == roster_digest,
            "signed_review_context_mismatch",
        )
        declaration = statement["conflict_of_interest"]
        _require(
            declaration in REVIEW_CONFLICT_DECLARATIONS,
            "reviewer_conflict_declaration_invalid",
        )
        if declaration != "none_declared":
            conflict_ids.add(reviewer_id)
        assessments = statement["assessments"]
        _require(isinstance(assessments, list), "review_assessments_not_list")
        _require(len(assessments) == len(witnessed_ids), "review_witness_count_mismatch")
        reviewed_ids: set[str] = set()
        for item in assessments:
            _require(
                isinstance(item, dict) and set(item) == {"witness_id", "domains"},
                "review_assessment_fields_invalid",
            )
            witness_id = item["witness_id"]
            _require(
                isinstance(witness_id, str) and witness_id in witnessed_ids,
                "review_unrecognized_witness",
            )
            _require(witness_id not in reviewed_ids, "review_duplicate_witness")
            reviewed_ids.add(witness_id)
            domains = item["domains"]
            _require(
                isinstance(domains, dict) and set(domains) == INDEPENDENCE_DOMAINS,
                "review_independence_domains_incomplete",
            )
            for domain in sorted(INDEPENDENCE_DOMAINS):
                record = domains[domain]
                _require(
                    isinstance(record, dict)
                    and set(record) == {"finding", "evidence_sha256"},
                    "review_domain_record_invalid",
                )
                _require(
                    isinstance(record["finding"], str)
                    and record["finding"] in REVIEW_FINDINGS,
                    "review_domain_finding_invalid",
                )
                _require(_sha256(record["evidence_sha256"]), "review_domain_evidence_invalid")
                if record["finding"] != "no_conflict_found":
                    unresolved_count += 1
        _require(reviewed_ids == witnessed_ids, "review_witness_coverage_incomplete")
        signature = statement["signature"]
        _require(_hex_bytes(signature, MLDSA65_SIGNATURE_BYTES), "review_signature_invalid")
        try:
            message = genesis_review_signing_message(statement)
        except (TypeError, ValueError, OverflowError) as exc:
            raise GenesisAcceptancePreflightError("review_statement_not_canonical_json") from exc
        _require(
            verify_signature_for_profile(
                sig_profile=PQ_MLDSA_V1,
                message=message,
                sig=signature,
                pubkey=reviewer_keys[reviewer_id],
            ),
            "review_signature_verification_failed",
        )
    _require(set(reviewer_keys) == signed_ids, "review_signer_set_incomplete")
    return GenesisIndependenceReviewPreflightEvidence(
        chain_id=genesis_binding.chain_id,
        genesis_manifest_sha256=genesis_binding.genesis_manifest_sha256,
        ceremony_id=witness_roster_binding.ceremony_id,
        witness_roster_sha256=witness_roster_binding.externally_pinned_roster_sha256,
        reviewer_roster_sha256=roster_digest,
        signed_reviewer_ids=tuple(sorted(signed_ids)),
        reviewed_witness_ids=tuple(sorted(witnessed_ids)),
        verified_domain_statements=len(signed_ids) * len(witnessed_ids) * len(INDEPENDENCE_DOMAINS),
        unresolved_domain_statements=unresolved_count,
        conflicted_or_unknown_reviewer_ids=tuple(sorted(conflict_ids)),
    )


__all__ = [
    "GenesisIndependenceReviewPreflightEvidence",
    "REVIEWER_ROSTER_SCHEMA",
    "SIGNED_REVIEW_SCHEMA",
    "genesis_review_signing_message",
    "preflight_signed_genesis_independence_reviews",
]
