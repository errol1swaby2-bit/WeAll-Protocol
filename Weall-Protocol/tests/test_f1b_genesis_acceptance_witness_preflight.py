"""Issue #87: cryptographic-only genesis ceremony witness preflight.

This reference does not establish four independence control domains, approve a
genesis-acceptance ceremony, mutate state, or authorize first solo finality.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.crypto.sig import sign_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.genesis_acceptance_witness import (
    SCHEMA,
    GenesisAcceptancePreflightError,
    canonical_genesis_witness_message,
    preflight_genesis_acceptance_signatures,
)

CHAIN_ID = "genesis-acceptance-witness-testnet"
GENESIS_SHA = hashlib.sha256(b"frozen-independent-genesis-manifest").hexdigest()
CEREMONY_ID = "genesis-ceremony-independent-witnesses-01"
DOMAINS = ("household", "funding", "key_custody", "infrastructure")


def _signed_candidate() -> tuple[dict[str, Any], str]:
    genesis_key = MLDSA65PrivateKey.generate().public_key().public_bytes_raw().hex()
    witnesses = []
    for number in range(3):
        key = MLDSA65PrivateKey.generate()
        witness_id = f"@genesis-external-witness-{number}"
        pubkey = key.public_key().public_bytes_raw().hex()
        commitments = {
            name: hashlib.sha256(f"{number}:{name}:private-evidence".encode()).hexdigest()
            for name in DOMAINS
        }
        message = canonical_genesis_witness_message(
            chain_id=CHAIN_ID,
            genesis_manifest_sha256=GENESIS_SHA,
            ceremony_id=CEREMONY_ID,
            witness_id=witness_id,
            pubkey=pubkey,
            independence_evidence_commitments=commitments,
        )
        signature = sign_signature_for_profile(
            sig_profile=PQ_MLDSA_V1,
            message=message,
            privkey=key.private_bytes_raw().hex(),
        )
        witnesses.append(
            {
                "witness_id": witness_id,
                "pubkey": pubkey,
                "sig_profile": PQ_MLDSA_V1,
                "signature": signature,
                "independence_evidence_commitments": commitments,
            }
        )
    return (
        {
            "schema": SCHEMA,
            "chain_id": CHAIN_ID,
            "genesis_manifest_sha256": GENESIS_SHA,
            "ceremony_id": CEREMONY_ID,
            "witnesses": witnesses,
        },
        genesis_key,
    )


@pytest.fixture
def ceremony(monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], str]:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.delenv("WEALL_CRYPTO_MODE", raising=False)
    return _signed_candidate()


def _preflight(certificate: dict[str, Any], genesis_key: str):
    return preflight_genesis_acceptance_signatures(
        certificate=certificate,
        expected_chain_id=CHAIN_ID,
        expected_genesis_manifest_sha256=GENESIS_SHA,
        genesis_validator_pubkey=genesis_key,
    )


def test_three_real_mldsa_signatures_bind_genesis_chain_ceremony_and_private_evidence(
    ceremony: tuple[dict[str, Any], str],
) -> None:
    certificate, genesis_key = ceremony
    original = copy.deepcopy(certificate)
    proof = _preflight(certificate, genesis_key)
    assert proof.cryptographically_verified_signatures == 3
    assert proof.chain_id == CHAIN_ID
    assert proof.genesis_manifest_sha256 == GENESIS_SHA
    assert proof.ceremony_id == CEREMONY_ID
    assert len(proof.witness_ids) == 3
    assert proof.external_independence_review_required is True
    assert proof.authorizes_first_finality is False
    assert certificate == original

    # Witness order must not affect the verified identity set or input evidence.
    reversed_cert = copy.deepcopy(certificate)
    reversed_cert["witnesses"].reverse()
    assert _preflight(reversed_cert, genesis_key) == proof


@pytest.mark.parametrize(
    ("attack", "reason"),
    [
        ("two_witnesses", "external_witness_threshold_not_met"),
        ("duplicate_witness_id", "duplicate_witness_identity"),
        ("duplicate_signing_key", "duplicate_witness_signing_key"),
        ("genesis_signer_as_external", "genesis_validator_not_external_witness"),
        ("changed_chain", "certificate_chain_mismatch"),
        ("changed_manifest", "certificate_manifest_mismatch"),
        ("changed_ceremony", "witness_signature_verification_failed"),
        ("changed_witness_id", "witness_signature_verification_failed"),
        ("changed_evidence_commitment", "witness_signature_verification_failed"),
        ("missing_independence_domain", "witness_independence_evidence_fields_invalid"),
        ("invalid_evidence_digest", "witness_independence_evidence_commitment_invalid"),
        ("invalid_signature_profile", "witness_signature_profile_invalid"),
        ("tampered_signature", "witness_signature_verification_failed"),
        ("extra_certificate_field", "certificate_fields_invalid"),
        ("extra_witness_field", "witness_fields_invalid"),
    ],
)
def test_genesis_witness_preflight_fails_closed_on_adversarial_vectors(
    ceremony: tuple[dict[str, Any], str], attack: str, reason: str
) -> None:
    certificate, genesis_key = ceremony
    modified = copy.deepcopy(certificate)
    a, b = modified["witnesses"][:2]
    if attack == "two_witnesses":
        modified["witnesses"].pop()
    elif attack == "duplicate_witness_id":
        b["witness_id"] = a["witness_id"]
    elif attack == "duplicate_signing_key":
        b["pubkey"] = a["pubkey"]
    elif attack == "genesis_signer_as_external":
        a["pubkey"] = genesis_key
    elif attack == "changed_chain":
        modified["chain_id"] = "another-chain"
    elif attack == "changed_manifest":
        modified["genesis_manifest_sha256"] = hashlib.sha256(b"other-genesis").hexdigest()
    elif attack == "changed_ceremony":
        modified["ceremony_id"] = "replayed-in-another-ceremony"
    elif attack == "changed_witness_id":
        a["witness_id"] = "@forged-identity"
    elif attack == "changed_evidence_commitment":
        a["independence_evidence_commitments"]["funding"] = hashlib.sha256(
            b"substituted-funding-evidence"
        ).hexdigest()
    elif attack == "missing_independence_domain":
        del a["independence_evidence_commitments"]["household"]
    elif attack == "invalid_evidence_digest":
        a["independence_evidence_commitments"]["key_custody"] = "00"
    elif attack == "invalid_signature_profile":
        a["sig_profile"] = "legacy-ed25519-v1"
    elif attack == "tampered_signature":
        sig = a["signature"]
        a["signature"] = f"{int(sig[:2], 16) ^ 1:02x}{sig[2:]}"
    elif attack == "extra_certificate_field":
        modified["founder_override"] = True
    elif attack == "extra_witness_field":
        a["is_validator"] = True
    else:
        pytest.fail(f"unknown vector: {attack}")

    with pytest.raises(GenesisAcceptancePreflightError, match=reason):
        _preflight(modified, genesis_key)


def test_trusted_manifest_and_validator_key_are_never_taken_from_untrusted_receipt(
    ceremony: tuple[dict[str, Any], str],
) -> None:
    certificate, genesis_key = ceremony
    wrong_manifest = hashlib.sha256(b"different-independent-build").hexdigest()
    with pytest.raises(GenesisAcceptancePreflightError, match="certificate_manifest_mismatch"):
        preflight_genesis_acceptance_signatures(
            certificate=certificate,
            expected_chain_id=CHAIN_ID,
            expected_genesis_manifest_sha256=wrong_manifest,
            genesis_validator_pubkey=genesis_key,
        )
    with pytest.raises(
        GenesisAcceptancePreflightError, match="trusted_genesis_validator_key_invalid"
    ):
        _preflight(certificate, "not-a-trusted-ml-dsa-validator-key")
