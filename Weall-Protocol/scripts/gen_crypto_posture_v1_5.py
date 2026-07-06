#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weall.crypto.pq_mldsa import mldsa_backend_status
from weall.crypto.signature_profiles import signature_profile_registry_json

Json = dict[str, Any]

CRYPTO_INVENTORY: list[Json] = [
    {"surface":"transaction_signatures","current_algorithm":"legacy-ed25519-v1 compatibility plus profile gate","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"account_keys","current_algorithm":"legacy pubkey fields plus profile-aware schema helper","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"account_recovery_keys","current_algorithm":"not fully migrated","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"validator_operator_signatures","current_algorithm":"legacy/profile-incomplete in some runtime flows","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"block_signatures","current_algorithm":"profile metadata gate added; real verifier depends on ML-DSA backend","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"bft_qc_signatures","current_algorithm":"classical/profile-incomplete HotStuff/QC signatures remain gated","target_algorithm":"pq-mldsa-v1 or externally reviewed threshold/aggregate profile","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"seed_registry_signatures","current_algorithm":"checked-in legacy-ed25519-v1 transitional signature","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"public_testnet_trust_roots","current_algorithm":"allowed profile declares pq-mldsa-v1; legacy listed transitional only","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"validator_endpoint_advertisements","current_algorithm":"profile-aware helper added","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"peer_identity_signatures","current_algorithm":"Ed25519 remains in peer/gossip modules","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"gossip_signatures","current_algorithm":"Ed25519 remains in gossip helper","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"relay_signatures","current_algorithm":"not fully migrated","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"observer_onboarding_signatures","current_algorithm":"legacy helper paths remain","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"evidence_bundle_signatures_digests","current_algorithm":"SHA-256 digests and legacy signatures where present","target_algorithm":"pq-mldsa-v1 signatures plus documented digest policy","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"frontend_signing_assumptions","current_algorithm":"UI must not present Ed25519 as future testnet profile","target_algorithm":"pq-mldsa-v1 or controlled backend/dev signer","consensus_critical":False,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":True,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"local_wallet_key_storage_encryption","current_algorithm":"symmetric/local storage varies","target_algorithm":"AES-256-equivalent plus PQ-aware backup plan","consensus_critical":False,"account_custody":True,"observer_trust":False,"transport_or_local_only":True,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"transport_tls_assumptions","current_algorithm":"conventional TLS stack","target_algorithm":"TLS plus future pq-mlkem-v1/hybrid support where available","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":True,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
]


def build_inventory() -> Json:
    return {
        "schema": "weall.crypto_inventory.v1_5",
        "framing": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
        "public_only": True,
        "critical_quantum_surface": "protocol signing and authority, not private messaging encryption",
        "surfaces": CRYPTO_INVENTORY,
    }


def build_readiness() -> Json:
    status = mldsa_backend_status()
    real_mldsa = bool(status.get("available") is True)
    blockers = []
    if not real_mldsa:
        blockers.append("real_mldsa_backend_unavailable_or_unpinned")
    blockers.extend([
        "seed_registry_requires_pq_resign",
        "bft_qc_signature_profile_incomplete",
        "peer_gossip_relay_signature_migration_incomplete",
        "frontend_local_pq_signing_not_complete",
        "external_crypto_review_missing",
    ])
    return {
        "schema": "weall.quantum_resistance_readiness.v1_5",
        "framing": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
        "controlled_testnet_target_profile": "pq-mldsa-v1",
        "legacy_profile": "legacy-ed25519-v1",
        "real_mldsa_implemented_in_this_environment": real_mldsa,
        "mldsa_backend_status": status,
        "ed25519_legacy_transitional_dev_only": True,
        "quantum_proof_claimed": False,
        "production_post_quantum_security_claimed": False,
        "production_crypto_audit_complete": False,
        "public_mainnet_ready": False,
        "public_beta_ready": False,
        "live_economics": False,
        "public_multi_validator_bft_ready": False,
        "remaining_crypto_blockers": blockers,
        "acceptable_claim_if_scaffolding_only": "WeAll remains a pre-public-testnet protocol implementation under active hardening. This patch adds fail-closed post-quantum signature-profile scaffolding, but real quantum-safe signing remains blocked until a reproducible ML-DSA implementation is integrated and tested.",
    }


def _write(path: Path, payload: Json) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    out = ROOT / "generated"
    out.mkdir(exist_ok=True)
    outputs = {
        out / "crypto_inventory_v1_5.json": build_inventory(),
        out / "signature_profile_registry_v1_5.json": signature_profile_registry_json(),
        out / "quantum_resistance_readiness_v1_5.json": build_readiness(),
    }
    for path, payload in outputs.items():
        _write(path, payload)
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
