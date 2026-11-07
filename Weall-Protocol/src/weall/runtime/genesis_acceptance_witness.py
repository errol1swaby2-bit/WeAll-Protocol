from __future__ import annotations

"""Reference-only signed genesis-acceptance witness preflight.

GEN-012 and BSTR-032 require external witnesses and independence review.
A cryptographically valid signature is NOT proof of independence, genesis
ceremony acceptance, validator membership, or first-finality authority.

This module is deliberately not imported by the ledger, scheduler, executor,
block builder, replay, or consensus voter. The preflight must never authorize
a BLOCK_FINALIZE or change a canonical state root.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from weall.crypto.pq_mldsa import MLDSA65_PUBLIC_KEY_BYTES, MLDSA65_SIGNATURE_BYTES
from weall.crypto.sig import verify_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1, profile_allowed_for_context
from weall.runtime.commitments import canonical_json_sha256
from weall.runtime.state_hash import compute_state_root

Json = dict[str, Any]
SCHEMA = "weall.genesis-acceptance.preflight.v1"
SIGNATURE_DOMAIN = b"weall.genesis-acceptance.external-witness.preflight.v1\x00"
INDEPENDENCE_DOMAINS = frozenset({"household", "funding", "key_custody", "infrastructure"})
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


@dataclass(frozen=True, slots=True)
class GenesisManifestBindingEvidence:
    """Only immutable manifest and signing evidence; never approval authority."""

    chain_id: str
    genesis_manifest_sha256: str
    genesis_hash: str
    genesis_state_root: str
    genesis_validator_account: str
    genesis_validator_pubkey_sha256: str
    witness_signatures: GenesisAcceptanceSignatureEvidence
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


def preflight_genesis_manifest_witness_binding(
    *,
    certificate: Json,
    manifest: Json,
    genesis_ledger: Json,
    expected_manifest_sha256: str,
    expected_chain_id: str,
) -> GenesisManifestBindingEvidence:
    """Bind witness signatures to a *separately trusted*, unmodified genesis.

    This checks the current production genesis builder's canonical manifest,
    genesis hash, state root, and founder key authority. It never accepts a
    manifest digest supplied *only* by the witness certificate as a trust root,
    and never imports mutable chain state as a substitute for height-zero
    evidence. A separate externally ratified acceptance rule is still needed.

    The production genesis builder has historically emitted a 32-byte hex
    founder *fingerprint* despite requiring an ML-DSA-65 validator signature.
    This preflight rejects that source state rather than silently accepting
    it as independent finality authority.
    """
    _require(isinstance(manifest, dict), "genesis_manifest_not_object")
    _require(isinstance(genesis_ledger, dict), "genesis_ledger_not_object")
    _require(_sha256(expected_manifest_sha256), "trusted_manifest_digest_invalid")
    _require(_ident(expected_chain_id), "trusted_chain_id_invalid")
    try:
        digest = canonical_json_sha256(manifest)
    except (TypeError, ValueError, OverflowError) as exc:
        raise GenesisAcceptancePreflightError("genesis_manifest_not_canonical_json") from exc
    _require(digest == expected_manifest_sha256, "genesis_manifest_trust_anchor_mismatch")
    _require(manifest.get("chain_id") == expected_chain_id, "genesis_manifest_chain_mismatch")
    _require(genesis_ledger.get("chain_id") == expected_chain_id, "genesis_ledger_chain_mismatch")

    height = genesis_ledger.get("height")
    _require(type(height) is int and height == 0, "genesis_state_not_height_zero")
    _require(genesis_ledger.get("tip") in ("", None), "genesis_tip_already_advanced")
    _require(genesis_ledger.get("blocks") in (None, {}), "genesis_block_history_not_empty")
    _require(genesis_ledger.get("system_queue") in (None, []), "genesis_system_queue_not_empty")
    finalized = genesis_ledger.get("finalized")
    _require(
        finalized is False
        or (
            isinstance(finalized, dict)
            and type(finalized.get("height")) is int
            and finalized["height"] == 0
            and finalized.get("block_id") in ("", None)
        ),
        "genesis_already_finalized",
    )
    consensus = genesis_ledger.get("consensus")
    _require(isinstance(consensus, dict), "genesis_consensus_registry_missing")
    phase = consensus.get("phase")
    if phase is not None:
        _require(
            isinstance(phase, dict) and phase.get("current") == "solo_bootstrap",
            "genesis_phase_not_solo",
        )
    epochs = consensus.get("epochs")
    if epochs is not None:
        _require(
            isinstance(epochs, dict) and epochs.get("current") == 0,
            "genesis_epoch_not_zero",
        )
    roles = genesis_ledger.get("roles")
    validators_role = roles.get("validators") if isinstance(roles, dict) else None
    members = validators_role.get("active_set") if isinstance(validators_role, dict) else None
    _require(
        isinstance(members, list)
        and len(members) == 1
        and _ident(members[0]),
        "genesis_single_validator_required",
    )
    founding_account = members[0]
    validator_set = consensus.get("validator_set")
    if validator_set is not None:
        _require(
            isinstance(validator_set, dict)
            and validator_set.get("active_set") == [founding_account],
            "genesis_consensus_membership_mismatch",
        )

    params = genesis_ledger.get("params")
    _require(isinstance(params, dict), "genesis_bootstrap_params_missing")
    _require(
        params.get("bootstrap_founder_account") == founding_account,
        "genesis_founder_account_mismatch",
    )
    operators = roles.get("node_operators")
    _require(
        isinstance(operators, dict)
        and operators.get("active_set") == [founding_account],
        "genesis_node_operator_authority_mismatch",
    )
    registry_root = consensus.get("validators")
    registry = registry_root.get("registry") if isinstance(registry_root, dict) else None
    lifecycle_root = genesis_ledger.get("validators")
    lifecycle = (
        lifecycle_root.get("registry") if isinstance(lifecycle_root, dict) else None
    )
    _require(
        isinstance(registry, dict) and isinstance(lifecycle, dict),
        "genesis_validator_registries_missing",
    )
    _require(
        set(registry) == {founding_account} and set(lifecycle) == {founding_account},
        "genesis_validator_registry_membership_mismatch",
    )
    consensus_rec = registry[founding_account]
    lifecycle_rec = lifecycle[founding_account]
    _require(
        isinstance(consensus_rec, dict) and isinstance(lifecycle_rec, dict),
        "genesis_validator_registry_record_invalid",
    )
    pubkey = consensus_rec.get("pubkey")
    _require(
        _hex_bytes(pubkey, MLDSA65_PUBLIC_KEY_BYTES),
        "genesis_validator_mldsa65_pubkey_invalid",
    )
    _require(
        lifecycle_rec.get("pubkey") == pubkey,
        "genesis_validator_registry_key_mismatch",
    )
    operator_records = operators.get("by_id")
    operator_record = (
        operator_records.get(founding_account)
        if isinstance(operator_records, dict)
        else None
    )
    responsibilities = (
        operator_record.get("responsibilities")
        if isinstance(operator_record, dict)
        else None
    )
    responsibility = (
        responsibilities.get("validator")
        if isinstance(responsibilities, dict)
        else None
    )
    _require(
        isinstance(responsibility, dict)
        and responsibility.get("bft_pubkey") == pubkey,
        "genesis_node_operator_signing_key_mismatch",
    )
    allowlist = params.get("bootstrap_allowlist")
    founder_allow = allowlist.get(founding_account) if isinstance(allowlist, dict) else None
    _require(
        isinstance(founder_allow, dict) and founder_allow.get("pubkey") == pubkey,
        "genesis_founder_allowlist_key_mismatch",
    )
    accounts = genesis_ledger.get("accounts")
    founding_rec = accounts.get(founding_account) if isinstance(accounts, dict) else None
    keys = founding_rec.get("keys") if isinstance(founding_rec, dict) else None
    by_id = keys.get("by_id") if isinstance(keys, dict) else None
    _require(
        isinstance(by_id, dict)
        and any(
            isinstance(rec, dict)
            and rec.get("pubkey") == pubkey
            and rec.get("revoked") is False
            for rec in by_id.values()
        ),
        "genesis_founder_account_signing_key_mismatch",
    )

    devices = founding_rec.get("devices")
    by_device_id = devices.get("by_id") if isinstance(devices, dict) else None
    node_device = (
        by_device_id.get("node:founding") if isinstance(by_device_id, dict) else None
    )
    _require(
        isinstance(node_device, dict)
        and node_device.get("pubkey") == pubkey
        and node_device.get("active") is True
        and node_device.get("revoked") is False,
        "genesis_node_device_signing_key_mismatch",
    )

    try:
        genesis_hash = canonical_json_sha256(genesis_ledger)
        state_root = compute_state_root(genesis_ledger)
    except (TypeError, ValueError, OverflowError) as exc:
        raise GenesisAcceptancePreflightError("genesis_ledger_not_canonical_json") from exc
    _require(manifest.get("genesis_hash") == genesis_hash, "genesis_hash_mismatch")
    _require(manifest.get("genesis_state_root") == state_root, "genesis_state_root_mismatch")
    meta = genesis_ledger.get("meta")
    _require(isinstance(meta, dict), "genesis_protocol_metadata_missing")
    _require(
        manifest.get("tx_index_hash") == meta.get("tx_index_hash")
        and _sha256(manifest.get("tx_index_hash")),
        "genesis_tx_index_hash_mismatch",
    )
    _require(
        manifest.get("protocol_profile_hash") == meta.get("production_consensus_profile_hash")
        and _sha256(manifest.get("protocol_profile_hash")),
        "genesis_consensus_profile_hash_mismatch",
    )

    witness_evidence = preflight_genesis_acceptance_signatures(
        certificate=certificate,
        expected_chain_id=expected_chain_id,
        expected_genesis_manifest_sha256=digest,
        genesis_validator_pubkey=pubkey,
    )
    return GenesisManifestBindingEvidence(
        chain_id=expected_chain_id,
        genesis_manifest_sha256=digest,
        genesis_hash=genesis_hash,
        genesis_state_root=state_root,
        genesis_validator_account=founding_account,
        genesis_validator_pubkey_sha256=hashlib.sha256(bytes.fromhex(pubkey)).hexdigest(),
        witness_signatures=witness_evidence,
    )


__all__ = [
    "GenesisAcceptancePreflightError",
    "GenesisAcceptanceSignatureEvidence",
    "GenesisManifestBindingEvidence",
    "canonical_genesis_witness_message",
    "preflight_genesis_acceptance_signatures",
    "preflight_genesis_manifest_witness_binding",
]
