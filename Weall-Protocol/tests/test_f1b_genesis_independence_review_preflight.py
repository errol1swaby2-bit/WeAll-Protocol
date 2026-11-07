"""Reference-only genesis review: real ML-DSA signatures, no acceptance power."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.crypto.sig import sign_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.commitments import canonical_json_sha256
from weall.runtime.genesis_acceptance_witness import (
    GenesisAcceptancePreflightError,
    GenesisAcceptanceSignatureEvidence,
    GenesisManifestBindingEvidence,
    GenesisWitnessRosterEvidence,
)
from weall.runtime.genesis_independence_review import (
    REVIEWER_ROSTER_SCHEMA,
    SIGNED_REVIEW_SCHEMA,
    genesis_review_signing_message,
    preflight_signed_genesis_independence_reviews,
)

DOMAINS = ("funding", "household", "infrastructure", "key_custody")
CHAIN = "review-only-testnet"
MANIFEST = hashlib.sha256(b"trusted-independent-genesis").hexdigest()
CEREMONY = "review-candidate-01"


def _new_key() -> tuple[MLDSA65PrivateKey, str]:
    private = MLDSA65PrivateKey.generate()
    return private, private.public_key().public_bytes_raw().hex()


def _sign(statement: dict[str, Any], private_hex: str) -> None:
    statement["signature"] = sign_signature_for_profile(
        sig_profile=PQ_MLDSA_V1,
        message=genesis_review_signing_message(statement),
        privkey=private_hex,
    )


@pytest.fixture
def signed_dossier(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.delenv("WEALL_CRYPTO_MODE", raising=False)
    _founder_private, founder_key = _new_key()
    witnesses = []
    for i in range(3):
        _private, key = _new_key()
        witnesses.append({"witness_id": f"@witness-{i}", "pubkey": key})
    witness_roster = {
        "schema": "weall.genesis-witness-roster.preflight.v1",
        "chain_id": CHAIN,
        "genesis_manifest_sha256": MANIFEST,
        "ceremony_id": CEREMONY,
        "witnesses": witnesses,
    }
    witness_sha = canonical_json_sha256(witness_roster)
    signed_certificate = GenesisAcceptanceSignatureEvidence(
        chain_id=CHAIN,
        genesis_manifest_sha256=MANIFEST,
        ceremony_id=CEREMONY,
        witness_ids=tuple(sorted(x["witness_id"] for x in witnesses)),
        cryptographically_verified_signatures=3,
    )
    binding = GenesisManifestBindingEvidence(
        chain_id=CHAIN,
        genesis_manifest_sha256=MANIFEST,
        genesis_hash=hashlib.sha256(b"genesis-ledger").hexdigest(),
        genesis_state_root=hashlib.sha256(b"genesis-state").hexdigest(),
        genesis_validator_account="@founder",
        genesis_validator_pubkey_sha256=hashlib.sha256(bytes.fromhex(founder_key)).hexdigest(),
        witness_signatures=signed_certificate,
    )
    witness_binding = GenesisWitnessRosterEvidence(
        chain_id=CHAIN,
        genesis_manifest_sha256=MANIFEST,
        ceremony_id=CEREMONY,
        externally_pinned_roster_sha256=witness_sha,
        witness_ids=signed_certificate.witness_ids,
    )
    reviewers = []
    private_keys = []
    for i in range(2):
        private, key = _new_key()
        private_keys.append(private.private_bytes_raw().hex())
        reviewers.append({"reviewer_id": f"@reviewer-{i}", "pubkey": key})
    reviewer_roster = {
        "schema": REVIEWER_ROSTER_SCHEMA,
        "chain_id": CHAIN,
        "genesis_manifest_sha256": MANIFEST,
        "ceremony_id": CEREMONY,
        "witness_roster_sha256": witness_sha,
        "reviewers": reviewers,
    }
    reviewer_sha = canonical_json_sha256(reviewer_roster)
    reviews = []
    for i, reviewer in enumerate(reviewers):
        assessments = [
            {
                "witness_id": witness["witness_id"],
                "domains": {
                    domain: {
                        "finding": "no_conflict_found",
                        "evidence_sha256": hashlib.sha256(
                            f"{i}:{witness['witness_id']}:{domain}:private-record".encode()
                        ).hexdigest(),
                    }
                    for domain in DOMAINS
                },
            }
            for witness in witnesses
        ]
        statement = {
            "schema": SIGNED_REVIEW_SCHEMA,
            "chain_id": CHAIN,
            "genesis_manifest_sha256": MANIFEST,
            "ceremony_id": CEREMONY,
            "witness_roster_sha256": witness_sha,
            "reviewer_roster_sha256": reviewer_sha,
            "reviewer_id": reviewer["reviewer_id"],
            "pubkey": reviewer["pubkey"],
            "sig_profile": PQ_MLDSA_V1,
            "conflict_of_interest": "none_declared",
            "assessments": assessments,
        }
        _sign(statement, private_keys[i])
        reviews.append(statement)
    return {
        "genesis_binding": binding,
        "witness_roster_binding": witness_binding,
        "witness_roster": witness_roster,
        "genesis_validator_pubkey": founder_key,
        "reviewer_roster": reviewer_roster,
        "expected_reviewer_roster_sha256": reviewer_sha,
        "signed_reviews": reviews,
        "reviewer_privates": private_keys,
    }


def _run(data: dict[str, Any]):
    return preflight_signed_genesis_independence_reviews(
        reviewer_roster=data["reviewer_roster"],
        expected_reviewer_roster_sha256=data["expected_reviewer_roster_sha256"],
        signed_reviews=data["signed_reviews"],
        genesis_binding=data["genesis_binding"],
        witness_roster_binding=data["witness_roster_binding"],
        witness_roster=data["witness_roster"],
        genesis_validator_pubkey=data["genesis_validator_pubkey"],
    )


def test_real_signed_reviewers_complete_four_domains_without_finality_authority(
    signed_dossier: dict[str, Any],
) -> None:
    before = copy.deepcopy(signed_dossier)
    result = _run(signed_dossier)
    assert result.verified_domain_statements == 2 * 3 * 4
    assert result.unresolved_domain_statements == 0
    assert result.reviewed_witness_ids == ("@witness-0", "@witness-1", "@witness-2")
    assert result.signed_reviewer_ids == ("@reviewer-0", "@reviewer-1")
    assert result.evidence_status == "signed_review_provenance_only"
    assert result.real_world_independence_verified is False
    assert result.constitutional_approval_recorded is False
    assert result.authorizes_first_finality is False
    assert signed_dossier == before
    reordered = copy.deepcopy(signed_dossier)
    reordered["signed_reviews"].reverse()
    reordered["reviewer_roster"]["reviewers"].reverse()
    reordered["witness_roster"]["witnesses"].reverse()
    # The separately pinned canonical digests protect roster order/content:
    # only signature order is immaterial, not silently changed roster bytes.
    reordered["reviewer_roster"] = before["reviewer_roster"]
    reordered["witness_roster"] = before["witness_roster"]
    assert _run(reordered) == result


def test_signed_conflict_and_insufficient_evidence_are_preserved_without_approval(
    signed_dossier: dict[str, Any],
) -> None:
    data = copy.deepcopy(signed_dossier)
    statement = data["signed_reviews"][0]
    statement["conflict_of_interest"] = "conflict_declared"
    statement["assessments"][0]["domains"]["funding"]["finding"] = "conflict_found"
    statement["assessments"][1]["domains"]["household"]["finding"] = "insufficient_evidence"
    _sign(statement, data["reviewer_privates"][0])
    result = _run(data)
    assert result.unresolved_domain_statements == 2
    assert result.conflicted_or_unknown_reviewer_ids == ("@reviewer-0",)
    assert result.real_world_independence_verified is False
    assert result.authorizes_first_finality is False


@pytest.mark.parametrize(
    ("attack", "reason"),
    [
        ("self_calculated_new_roster", "reviewer_roster_anchor_mismatch"),
        ("alter_roster_chain", "reviewer_roster_chain_mismatch"),
        ("reviewer_key_swapped", "reviewer_public_key_mismatch"),
        ("reviewer_duplicate_id", "duplicate_reviewer_identity"),
        ("reviewer_duplicate_key", "duplicate_reviewer_public_key"),
        ("reviewer_is_witness", "reviewer_key_role_reuse"),
        ("reviewer_is_founder", "reviewer_key_role_reuse"),
        ("reviewer_missing", "reviewer_roster_too_small"),
        ("signature_tampered", "review_signature_verification_failed"),
        ("signed_evidence_mutated", "review_signature_verification_failed"),
        ("signed_domain_missing", "review_independence_domains_incomplete"),
        ("signed_witness_missing", "review_witness_count_mismatch"),
        ("signed_witness_duplicate", "review_duplicate_witness"),
        ("signed_context_changed", "signed_review_context_mismatch"),
        ("reviewer_undeclared", "unapproved_review_signer"),
        ("conflict_declaration_invalid", "reviewer_conflict_declaration_invalid"),
        ("unapproved_domain_finding", "review_domain_finding_invalid"),
        ("fake_approval_flag", "signed_review_fields_invalid"),
        ("extra_reviewer_signature", "review_signer_count_mismatch"),
    ],
)
def test_adversarial_signed_review_evidence_fails_closed(
    signed_dossier: dict[str, Any],
    attack: str,
    reason: str,
) -> None:
    data = copy.deepcopy(signed_dossier)
    reviewers = data["reviewer_roster"]["reviewers"]
    reviews = data["signed_reviews"]
    if attack == "self_calculated_new_roster":
        reviewers[0]["reviewer_id"] = "@attacker"
    elif attack == "alter_roster_chain":
        data["reviewer_roster"]["chain_id"] = "attacker-chain"
    elif attack == "reviewer_key_swapped":
        reviews[0]["pubkey"] = reviews[1]["pubkey"]
    elif attack == "reviewer_duplicate_id":
        reviewers[1]["reviewer_id"] = reviewers[0]["reviewer_id"]
    elif attack == "reviewer_duplicate_key":
        reviewers[1]["pubkey"] = reviewers[0]["pubkey"]
    elif attack == "reviewer_is_witness":
        reviewers[0]["pubkey"] = data["witness_roster"]["witnesses"][0]["pubkey"]
    elif attack == "reviewer_is_founder":
        reviewers[0]["pubkey"] = data["genesis_validator_pubkey"]
    elif attack == "reviewer_missing":
        reviewers.pop()
        reviews.pop()
    elif attack == "signature_tampered":
        sig = reviews[0]["signature"]
        reviews[0]["signature"] = f"{int(sig[:2], 16) ^ 1:02x}{sig[2:]}"
    elif attack == "signed_evidence_mutated":
        reviews[0]["assessments"][0]["domains"]["household"]["evidence_sha256"] = "0" * 64
    elif attack == "signed_domain_missing":
        del reviews[0]["assessments"][0]["domains"]["key_custody"]
    elif attack == "signed_witness_missing":
        reviews[0]["assessments"].pop()
    elif attack == "signed_witness_duplicate":
        reviews[0]["assessments"][1]["witness_id"] = reviews[0]["assessments"][0]["witness_id"]
    elif attack == "signed_context_changed":
        reviews[0]["ceremony_id"] = "different-ceremony"
    elif attack == "reviewer_undeclared":
        reviews[0]["reviewer_id"] = "@unknown"
    elif attack == "conflict_declaration_invalid":
        reviews[0]["conflict_of_interest"] = "certified"
    elif attack == "unapproved_domain_finding":
        reviews[0]["assessments"][0]["domains"]["funding"]["finding"] = "automatically_approved"
    elif attack == "fake_approval_flag":
        reviews[0]["constitutional_approval"] = True
    elif attack == "extra_reviewer_signature":
        reviews.append(copy.deepcopy(reviews[0]))
    else:
        pytest.fail(f"unexpected attack: {attack}")
    if attack in {
        "alter_roster_chain", "reviewer_duplicate_id", "reviewer_duplicate_key",
        "reviewer_is_witness", "reviewer_is_founder", "reviewer_missing",
    }:
        data["expected_reviewer_roster_sha256"] = canonical_json_sha256(data["reviewer_roster"])
    with pytest.raises(GenesisAcceptancePreflightError, match=reason):
        _run(data)
