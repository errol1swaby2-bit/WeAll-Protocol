from __future__ import annotations

"""Reference-only signed genesis-acceptance witness preflight.

GEN-012 and BSTR-032 require external witnesses and independence review.
A cryptographically valid signature is NOT proof of independence, genesis
ceremony acceptance, validator membership, or first-finality authority.

This module is deliberately not imported by the ledger, scheduler, executor,
block builder, replay, or consensus voter. The preflight must never authorize
a BLOCK_FINALIZE or change a canonical state root.
"""

import json
import re
from dataclasses import dataclass
from typing import Any

from weall.crypto.pq_mldsa import MLDSA65_PUBLIC_KEY_BYTES, MLDSA65_SIGNATURE_BYTES
from weall.crypto.sig import verify_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1, profile_allowed_for_context

Json = dict[str, Any]
SCHEMA = "weall.genesis-acceptance.preflight.v1"
SIGNATURE_DOMAIN = b"weall.genesis-acceptance.external-witness.preflight.v1\x00"
INDEPENDENCE_DOMAINS = frozenset(
    {"household", "funding", "key_custody", "infrastructure"}
)
MIN_EXTERNAL_WITNESSES = 3
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class GenesisAcceptancePreflightError(ValueError):
    """A candidate witness receipt fails a cryptographic preflight invariant."""


@dataclass(frozen=True, slots=True)
class GenesisAcceptanceSignatureEvidence:
    chain_id: str
    genesis_manifest_sha256: str
    ceremony_id: str
    witness_ids: tuple[str, ...]
    cryptographically_verified_signatures: int
    # A cryptographic signature count is never a constitutional decision.
    external_independence_review_required: bool = True
    authorizes_first_finality: bool = False


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise GenesisAcceptancePreflightError(reason)


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and _HEX_SHA256.fullmatch(value) is not None


def _hex_bytes(value: Any, count: int) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == count * 2
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


def _ident(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 128
        and value == value.strip()
        and all(c not in value for c in ("\n", "\r", "\x00"))
    )


def canonical_genesis_witness_message(
    *,
    chain_id: str,
    genesis_manifest_sha256: str,
    ceremony_id: str,
    witness_id: str,
    pubkey: str,
    independence_evidence_commitments: Json,
) -> bytes:
    """Proposed distinct signing domain; not an adopted genesis wire format.

    The accepted genesis hash is supplied from outside the certificate:
    witnesses sign the already frozen manifest digest rather than a circular
    genesis state hash containing their own signatures. Commitments expose no
    raw household, financial, key-custody, or infrastructure information.
    """
    body = {
        "schema": SCHEMA,
        "chain_id": chain_id,
        "genesis_manifest_sha256": genesis_manifest_sha256,
        "ceremony_id": ceremony_id,
        "witness_id": witness_id,
        "pubkey": pubkey,
        "independence_evidence_commitments": independence_evidence_commitments,
    }
    return SIGNATURE_DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def preflight_genesis_acceptance_signatures(
    *,
    certificate: Json,
    expected_chain_id: str,
    expected_genesis_manifest_sha256: str,
    genesis_validator_pubkey: str,
) -> GenesisAcceptanceSignatureEvidence:
    """Verify only immutable candidate external-witness signature evidence.

    The expected manifest digest and initial validator key must be independently
    established from a trusted clean-room genesis construction; it is unsafe to
    read those expected values solely from the untrusted certificate.

    Self-declared independence evidence digests cannot establish that different
    witnesses lack common household, funding, custody, or infrastructure
    control. A separate constitutional review remains mandatory even on success.
    """
    _require(isinstance(certificate, dict), "certificate_not_object")
    _require(
        set(certificate)
        == {
            "schema",
            "chain_id",
            "genesis_manifest_sha256",
            "ceremony_id",
            "witnesses",
        },
        "certificate_fields_invalid",
    )
    _require(certificate["schema"] == SCHEMA, "certificate_schema_invalid")
    _require(_ident(expected_chain_id), "trusted_chain_id_invalid")
    _require(_sha256(expected_genesis_manifest_sha256), "trusted_manifest_digest_invalid")
    _require(
        _hex_bytes(genesis_validator_pubkey, MLDSA65_PUBLIC_KEY_BYTES),
        "trusted_genesis_validator_key_invalid",
    )
    _require(certificate["chain_id"] == expected_chain_id, "certificate_chain_mismatch")
    _require(
        certificate["genesis_manifest_sha256"] == expected_genesis_manifest_sha256,
        "certificate_manifest_mismatch",
    )
    ceremony_id = certificate["ceremony_id"]
    _require(_ident(ceremony_id), "ceremony_id_invalid")

    profile_ok, _reason = profile_allowed_for_context(
        PQ_MLDSA_V1, purpose="signing", require_verifier=True
    )
    _require(profile_ok, "ceremony_signature_profile_unavailable")

    witnesses = certificate["witnesses"]
    _require(isinstance(witnesses, list), "witnesses_not_list")
    _require(len(witnesses) >= MIN_EXTERNAL_WITNESSES, "external_witness_threshold_not_met")
    seen_ids: set[str] = set()
    seen_pubkeys: set[str] = set()
    for raw in witnesses:
        _require(isinstance(raw, dict), "witness_not_object")
        _require(
            set(raw)
            == {
                "witness_id",
                "sig_profile",
                "pubkey",
                "independence_evidence_commitments",
                "signature",
            },
            "witness_fields_invalid",
        )
        witness_id = raw["witness_id"]
        _require(_ident(witness_id), "witness_id_invalid")
        _require(witness_id not in seen_ids, "duplicate_witness_identity")
        seen_ids.add(witness_id)
        _require(raw["sig_profile"] == PQ_MLDSA_V1, "witness_signature_profile_invalid")
        pubkey = raw["pubkey"]
        _require(_hex_bytes(pubkey, MLDSA65_PUBLIC_KEY_BYTES), "witness_pubkey_invalid")
        _require(pubkey != genesis_validator_pubkey, "genesis_validator_not_external_witness")
        _require(pubkey not in seen_pubkeys, "duplicate_witness_signing_key")
        seen_pubkeys.add(pubkey)

        evidence = raw["independence_evidence_commitments"]
        _require(
            isinstance(evidence, dict) and set(evidence) == INDEPENDENCE_DOMAINS,
            "witness_independence_evidence_fields_invalid",
        )
        _require(
            all(_sha256(value) for value in evidence.values()),
            "witness_independence_evidence_commitment_invalid",
        )
        signature = raw["signature"]
        _require(_hex_bytes(signature, MLDSA65_SIGNATURE_BYTES), "witness_signature_invalid")
        message = canonical_genesis_witness_message(
            chain_id=expected_chain_id,
            genesis_manifest_sha256=expected_genesis_manifest_sha256,
            ceremony_id=ceremony_id,
            witness_id=witness_id,
            pubkey=pubkey,
            independence_evidence_commitments=evidence,
        )
        _require(
            verify_signature_for_profile(
                sig_profile=PQ_MLDSA_V1, message=message, sig=signature, pubkey=pubkey
            ),
            "witness_signature_verification_failed",
        )

    return GenesisAcceptanceSignatureEvidence(
        chain_id=expected_chain_id,
        genesis_manifest_sha256=expected_genesis_manifest_sha256,
        ceremony_id=ceremony_id,
        witness_ids=tuple(sorted(seen_ids)),
        cryptographically_verified_signatures=len(seen_ids),
    )


__all__ = [
    "GenesisAcceptancePreflightError",
    "GenesisAcceptanceSignatureEvidence",
    "canonical_genesis_witness_message",
    "preflight_genesis_acceptance_signatures",
]
