"""Issue #87: cryptographic-only genesis ceremony witness preflight.

This reference does not establish four independence control domains, approve a
genesis-acceptance ceremony, mutate state, or authorize first solo finality.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.crypto.sig import sign_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.commitments import canonical_json_sha256
from weall.runtime.genesis_acceptance_witness import (
    ROSTER_SCHEMA,
    SCHEMA,
    GenesisAcceptancePreflightError,
    canonical_genesis_witness_message,
    preflight_genesis_acceptance_signatures,
    preflight_genesis_manifest_witness_binding,
    preflight_externally_pinned_genesis_witness_roster,
)
from weall.runtime.state_hash import compute_state_root

CHAIN_ID = "genesis-acceptance-witness-testnet"
GENESIS_SHA = hashlib.sha256(b"frozen-independent-genesis-manifest").hexdigest()
CEREMONY_ID = "genesis-ceremony-independent-witnesses-01"
DOMAINS = ("household", "funding", "key_custody", "infrastructure")


def _signed_candidate(
    *,
    chain_id: str = CHAIN_ID,
    manifest_sha256: str = GENESIS_SHA,
    genesis_validator_pubkey: str | None = None,
) -> tuple[dict[str, Any], str]:
    genesis_key = (
        genesis_validator_pubkey
        if genesis_validator_pubkey is not None
        else MLDSA65PrivateKey.generate().public_key().public_bytes_raw().hex()
    )
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
            chain_id=chain_id,
            genesis_manifest_sha256=manifest_sha256,
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
            "chain_id": chain_id,
            "genesis_manifest_sha256": manifest_sha256,
            "ceremony_id": CEREMONY_ID,
            "witnesses": witnesses,
        },
        genesis_key,
    )


def _externally_pinned_candidate_roster(
    certificate: dict[str, Any],
) -> dict[str, Any]:
    """Test-only roster: the digest is NOT a real independent trust anchor."""
    return {
        "schema": ROSTER_SCHEMA,
        "chain_id": certificate["chain_id"],
        "genesis_manifest_sha256": certificate["genesis_manifest_sha256"],
        "ceremony_id": certificate["ceremony_id"],
        "witnesses": sorted(
            [
                {"witness_id": w["witness_id"], "pubkey": w["pubkey"]}
                for w in certificate["witnesses"]
            ],
            key=lambda item: item["witness_id"],
        ),
    }


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


@pytest.fixture
def frozen_builder_genesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    """Use the actual production ceremony builder with a real ML-DSA signing key."""
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.delenv("WEALL_CRYPTO_MODE", raising=False)
    founder = MLDSA65PrivateKey.generate().public_key().public_bytes_raw().hex()
    root = Path(__file__).resolve().parents[1]
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}))
    genesis_path = tmp_path / "genesis.json"
    manifest_path = tmp_path / "manifest.json"
    chain_id = "genesis-manifest-binding-testnet"
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "build_production_genesis_manifest.py"),
            "--chain-id",
            chain_id,
            "--founding-account",
            "@genesis-manifest-founder",
            "--founding-pubkey",
            founder,
            "--authority-pubkey",
            "b" * 64,
            "--tx-index",
            str(tx_index),
            "--genesis-out",
            str(genesis_path),
            "--manifest-out",
            str(manifest_path),
            "--genesis-time",
            "1900000000",
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    ledger = json.loads(genesis_path.read_text())
    manifest = json.loads(manifest_path.read_text())
    trusted_sha = canonical_json_sha256(manifest)
    cert, _founder = _signed_candidate(
        chain_id=chain_id, manifest_sha256=trusted_sha, genesis_validator_pubkey=founder
    )
    return cert, manifest, ledger, trusted_sha


def _bind(
    data: tuple[dict[str, Any], dict[str, Any], dict[str, Any], str],
):
    certificate, manifest, ledger, digest = data
    return preflight_genesis_manifest_witness_binding(
        certificate=certificate,
        manifest=manifest,
        genesis_ledger=ledger,
        expected_manifest_sha256=digest,
        expected_chain_id="genesis-manifest-binding-testnet",
    )


def test_signatures_are_bound_to_actual_builder_genesis_state_and_manifest(
    frozen_builder_genesis: tuple[dict[str, Any], dict[str, Any], dict[str, Any], str],
) -> None:
    data = frozen_builder_genesis
    untouched = copy.deepcopy(data)
    proof = _bind(data)
    assert proof.chain_id == "genesis-manifest-binding-testnet"
    assert proof.genesis_manifest_sha256 == data[3]
    assert proof.genesis_hash == data[1]["genesis_hash"]
    assert proof.genesis_state_root == data[1]["genesis_state_root"]
    assert proof.genesis_validator_account == "@genesis-manifest-founder"
    assert len(proof.genesis_validator_pubkey_sha256) == 64
    assert proof.witness_signatures.cryptographically_verified_signatures == 3
    assert proof.witness_signatures.authorizes_first_finality is False
    assert proof.authorizes_first_finality is False
    assert proof.external_independence_review_required is True
    assert data == untouched

    # Independent read-only copies must produce precisely the same evidence.
    second = copy.deepcopy(data)
    second[0]["witnesses"].reverse()
    assert _bind(second) == proof


@pytest.mark.parametrize(
    ("attack", "expected_reason"),
    [
        ("manifest_replaced", "genesis_manifest_trust_anchor_mismatch"),
        ("ledger_replaced", "genesis_hash_mismatch"),
        ("height_advanced", "genesis_state_not_height_zero"),
        ("already_finalized", "genesis_already_finalized"),
        ("post_genesis_tip", "genesis_tip_already_advanced"),
        ("bft_phase", "genesis_phase_not_solo"),
        ("two_validators", "genesis_single_validator_required"),
        ("founder_alias", "genesis_founder_account_mismatch"),
        ("short_validator_key", "genesis_validator_mldsa65_pubkey_invalid"),
        ("lifecycle_key_diverges", "genesis_validator_registry_key_mismatch"),
        ("node_operator_key_diverges", "genesis_node_operator_signing_key_mismatch"),
        ("node_device_key_diverges", "genesis_node_device_signing_key_mismatch"),
        ("allowlist_key_diverges", "genesis_founder_allowlist_key_mismatch"),
        ("account_key_diverges", "genesis_founder_account_signing_key_mismatch"),
        ("stale_tx_index", "genesis_tx_index_hash_mismatch"),
        ("stale_protocol_profile", "genesis_consensus_profile_hash_mismatch"),
    ],
)
def test_builder_genesis_binding_rejects_ancestry_and_authority_substitution(
    frozen_builder_genesis: tuple[dict[str, Any], dict[str, Any], dict[str, Any], str],
    attack: str,
    expected_reason: str,
) -> None:
    cert, manifest, ledger, digest = copy.deepcopy(frozen_builder_genesis)
    founder = "@genesis-manifest-founder"
    if attack == "manifest_replaced":
        manifest["notes"] = "substituted manifest"
    elif attack == "ledger_replaced":
        ledger["accounts"][founder]["nonce"] = 7
    elif attack == "height_advanced":
        ledger["height"] = 1
    elif attack == "already_finalized":
        ledger["finalized"] = {"height": 1, "block_id": "fake"}
    elif attack == "post_genesis_tip":
        ledger["tip"] = "an-unfinalized-tip"
    elif attack == "bft_phase":
        ledger["consensus"]["phase"] = {"current": "bft_active"}
    elif attack == "two_validators":
        ledger["roles"]["validators"]["active_set"].append("@unsigned-second-validator")
    elif attack == "founder_alias":
        ledger["params"]["bootstrap_founder_account"] = "@not-founder"
    elif attack == "short_validator_key":
        ledger["consensus"]["validators"]["registry"][founder]["pubkey"] = "a" * 64
    elif attack == "lifecycle_key_diverges":
        ledger["validators"]["registry"][founder]["pubkey"] = "f" * 3904
    elif attack == "node_operator_key_diverges":
        ledger["roles"]["node_operators"]["by_id"][founder]["responsibilities"]["validator"][
            "bft_pubkey"
        ] = "f" * 3904
    elif attack == "node_device_key_diverges":
        ledger["accounts"][founder]["devices"]["by_id"]["node:founding"]["pubkey"] = "f" * 3904
    elif attack == "allowlist_key_diverges":
        ledger["params"]["bootstrap_allowlist"][founder]["pubkey"] = "f" * 3904
    elif attack == "account_key_diverges":
        by_id = ledger["accounts"][founder]["keys"]["by_id"]
        first_id = next(iter(by_id))
        by_id[first_id]["pubkey"] = "f" * 3904
    elif attack == "stale_tx_index":
        ledger["meta"]["tx_index_hash"] = "0" * 64
        manifest["genesis_hash"] = canonical_json_sha256(ledger)
        # The trust anchor must be updated separately; this creates a new,
        # signed-looking manifest only for testing the inner consistency guard.
        manifest["genesis_state_root"] = compute_state_root(ledger)
        digest = canonical_json_sha256(manifest)
        cert, _ = _signed_candidate(
            chain_id=cert["chain_id"],
            manifest_sha256=digest,
            genesis_validator_pubkey=ledger["consensus"]["validators"]["registry"][founder][
                "pubkey"
            ],
        )
    elif attack == "stale_protocol_profile":
        ledger["meta"]["production_consensus_profile_hash"] = "0" * 64
        manifest["genesis_hash"] = canonical_json_sha256(ledger)
        manifest["genesis_state_root"] = compute_state_root(ledger)
        digest = canonical_json_sha256(manifest)
        cert, _ = _signed_candidate(
            chain_id=cert["chain_id"],
            manifest_sha256=digest,
            genesis_validator_pubkey=ledger["consensus"]["validators"]["registry"][founder][
                "pubkey"
            ],
        )
    else:
        pytest.fail(f"unknown attack: {attack}")

    with pytest.raises(GenesisAcceptancePreflightError, match=expected_reason):
        _bind((cert, manifest, ledger, digest))


def test_signed_replacement_manifest_cannot_override_genesis_state_root(
    frozen_builder_genesis: tuple[dict[str, Any], dict[str, Any], dict[str, Any], str],
) -> None:
    original_cert, manifest, ledger, _ = frozen_builder_genesis
    rewritten_manifest = copy.deepcopy(manifest)
    rewritten_manifest["genesis_state_root"] = "0" * 64
    new_digest = canonical_json_sha256(rewritten_manifest)
    cert, _ = _signed_candidate(
        chain_id=original_cert["chain_id"],
        manifest_sha256=new_digest,
        genesis_validator_pubkey=ledger["consensus"]["validators"]["registry"][
            "@genesis-manifest-founder"
        ]["pubkey"],
    )
    with pytest.raises(GenesisAcceptancePreflightError, match="genesis_state_root_mismatch"):
        _bind((cert, rewritten_manifest, ledger, new_digest))


def test_external_genesis_witness_bundle_two_process_rebuild_and_cli_replay(
    frozen_builder_genesis: tuple[dict[str, Any], dict[str, Any], dict[str, Any], str],
    tmp_path: Path,
) -> None:
    """Independent OS processes can reproduce identical *candidate* evidence.

    Both producer and follower run the same implementation, so this is not
    independent clean-room implementation, constitutional witness independence,
    or authority to issue a first BLOCK_FINALIZE.
    """
    certificate, manifest, ledger, expected_digest = frozen_builder_genesis
    root = Path(__file__).resolve().parents[1]
    verifier = root / "scripts" / "preflight_genesis_witness_bundle.py"
    builder = root / "scripts" / "build_production_genesis_manifest.py"
    founder_pubkey = ledger["consensus"]["validators"]["registry"]["@genesis-manifest-founder"][
        "pubkey"
    ]
    expected_genesis = (json.dumps(ledger, indent=2, sort_keys=True) + "\n").encode()
    expected_manifest = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()

    roster = _externally_pinned_candidate_roster(certificate)
    pinned_roster_digest = canonical_json_sha256(roster)

    # Repeat the *frozen-time* production builder from two independent Python
    # processes. Reuse public inputs only; never export or fabricate production
    # private keys to create an "accepted" certificate.
    attestations: list[dict[str, Any]] = []
    for number in (1, 2):
        node_dir = tmp_path / f"node-{number}"
        node_dir.mkdir()
        tx_index = node_dir / "tx_index.json"
        tx_index.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}))
        genesis = node_dir / "genesis.json"
        manifest_path = node_dir / "manifest.json"
        result = subprocess.run(
            [
                sys.executable,
                str(builder),
                "--chain-id",
                "genesis-manifest-binding-testnet",
                "--founding-account",
                "@genesis-manifest-founder",
                "--founding-pubkey",
                founder_pubkey,
                "--authority-pubkey",
                "b" * 64,
                "--tx-index",
                str(tx_index),
                "--genesis-out",
                str(genesis),
                "--manifest-out",
                str(manifest_path),
                "--genesis-time",
                "1900000000",
            ],
            cwd=str(root),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr + result.stdout
        assert genesis.read_bytes() == expected_genesis
        assert manifest_path.read_bytes() == expected_manifest

        certificate_path = node_dir / "witness-certificate.json"
        certificate_path.write_text(json.dumps(certificate, sort_keys=True, indent=2))
        roster_path = node_dir / "external-witness-roster.json"
        roster_path.write_text(json.dumps(roster, sort_keys=True, indent=2))
        verified = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "--manifest",
                str(manifest_path),
                "--genesis",
                str(genesis),
                "--certificate",
                str(certificate_path),
                "--witness-roster",
                str(roster_path),
                "--trusted-witness-roster-sha256",
                pinned_roster_digest,
                "--trusted-manifest-sha256",
                expected_digest,
                "--expected-chain-id",
                "genesis-manifest-binding-testnet",
            ],
            cwd=str(root),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        assert verified.returncode == 0, verified.stderr + verified.stdout
        assertion = json.loads(verified.stdout)
        assert assertion["status"] == "cryptographic_preflight_only"
        assert assertion["scope"] == "reference_only"
        assert assertion["authority_decision"] == "not_performed"
        assert assertion["external_independence_review_required"] is True
        assert assertion["roster_validation_status"] == "signer_identity_and_key_binding_only"
        assert assertion["witness_roster_binding"]["externally_pinned_roster_sha256"] == (
            pinned_roster_digest
        )
        assert assertion["witness_roster_binding"]["authorizes_first_finality"] is False
        assert assertion["authorizes_first_finality"] is False
        assert assertion["evidence"]["genesis_manifest_sha256"] == expected_digest
        assert (
            assertion["evidence"]["witness_signatures"]["cryptographically_verified_signatures"]
            == 3
        )
        attestations.append(assertion)

    assert attestations[0] == attestations[1]


@pytest.mark.parametrize(
    ("attack", "reason"),
    [
        ("wrong_trusted_digest", "genesis_manifest_trust_anchor_mismatch"),
        ("wrong_trusted_chain", "genesis_manifest_chain_mismatch"),
        ("tampered_genesis", "genesis_hash_mismatch"),
        ("duplicate_manifest_key", "invalid_genesis_bundle_json"),
        ("nonfinite_genesis_number", "invalid_genesis_bundle_json"),
        ("invalid_certificate_root", "genesis_bundle_root_not_object"),
    ],
)
def test_offline_witness_cli_fail_closed_on_bundle_substitution(
    frozen_builder_genesis: tuple[dict[str, Any], dict[str, Any], dict[str, Any], str],
    tmp_path: Path,
    attack: str,
    reason: str,
) -> None:
    certificate, manifest, ledger, digest = copy.deepcopy(frozen_builder_genesis)
    root = Path(__file__).resolve().parents[1]
    manifest_path = tmp_path / "manifest.json"
    genesis_path = tmp_path / "genesis.json"
    certificate_path = tmp_path / "certificate.json"
    manifest_path.write_text(json.dumps(manifest))
    genesis_path.write_text(json.dumps(ledger))
    certificate_path.write_text(json.dumps(certificate))
    roster = _externally_pinned_candidate_roster(certificate)
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(roster))
    pinned_roster_digest = canonical_json_sha256(roster)
    chain = "genesis-manifest-binding-testnet"
    if attack == "wrong_trusted_digest":
        digest = "0" * 64
    elif attack == "wrong_trusted_chain":
        chain = "other-testnet"
    elif attack == "tampered_genesis":
        ledger["accounts"]["@genesis-manifest-founder"]["nonce"] = 9
        genesis_path.write_text(json.dumps(ledger))
    elif attack == "duplicate_manifest_key":
        manifest_path.write_text('{"chain_id":"x","chain_id":"x"}')
    elif attack == "nonfinite_genesis_number":
        genesis_path.write_text('{"height":NaN}')
    elif attack == "invalid_certificate_root":
        certificate_path.write_text("[]")
    else:
        pytest.fail(f"unknown attack: {attack}")

    checked = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "preflight_genesis_witness_bundle.py"),
            "--manifest",
            str(manifest_path),
            "--genesis",
            str(genesis_path),
            "--certificate",
            str(certificate_path),
            "--witness-roster",
            str(roster_path),
            "--trusted-witness-roster-sha256",
            pinned_roster_digest,
            "--trusted-manifest-sha256",
            digest,
            "--expected-chain-id",
            chain,
        ],
        cwd=str(root),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert checked.returncode == 2
    response = json.loads(checked.stdout)
    assert response["reason"] == reason
    assert response["ok"] is False
    assert response["authorizes_first_finality"] is False
