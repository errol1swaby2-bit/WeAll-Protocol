#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from weall.crypto.pq_mldsa import mldsa_backend_status
from weall.crypto.signature_profiles import PQ_MLDSA_V1, signature_profile_registry_json

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "generated"
GENERATED.mkdir(exist_ok=True)

SURFACES = [
    {"surface":"transaction_signatures","current_algorithm":"profile-aware pq-mldsa-v1 signing/verifying through pyca/cryptography ML-DSA-65 only","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"account_keys","current_algorithm":"profile-aware ML-DSA account key records only","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"account_recovery_keys","current_algorithm":"profile-aware ML-DSA recovery/key rotation records only","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"validator_operator_signatures","current_algorithm":"validator/operator records declare pq-mldsa-v1 and runtime admission rejects other signing profiles","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"block_signatures","current_algorithm":"block signature metadata and admission require pq-mldsa-v1/ML-DSA","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"bft_qc_signatures","current_algorithm":"HotStuff proposal/vote/timeout/QC surfaces are profile-aware and use pq-mldsa-v1","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"seed_registry_signatures","current_algorithm":"public seed registry verification requires pq-mldsa-v1","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"public_testnet_trust_roots","current_algorithm":"trust roots allow pq-mldsa-v1 only for public testnet registry verification","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"validator_endpoint_advertisements","current_algorithm":"validator endpoint advertisements are signed and verified with pq-mldsa-v1","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"peer_identity_signatures","current_algorithm":"PEER_HELLO identity proofs use pq-mldsa-v1 ML-DSA-65","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"gossip_signatures","current_algorithm":"peer gossip records use pq-mldsa-v1 signatures when signed","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"relay_signatures","current_algorithm":"relay access requests and relay envelopes use pq-mldsa-v1 when signed","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"observer_onboarding_signatures","current_algorithm":"observer onboarding evidence is tied to pq-mldsa-v1 trust-root/registry verification and must be rerun after migration","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"evidence_bundle_signatures_digests","current_algorithm":"evidence bundles are digest/manifest based; durable PQ signing policy remains a reviewer blocker","target_algorithm":"pq-mldsa-v1 evidence manifest signing","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"frontend_signing_assumptions","current_algorithm":"observer UI exposes active pq-mldsa-v1; browser signing must use a controlled ML-DSA-capable signer until browser-native support is complete","target_algorithm":"pq-mldsa-v1 controlled signer or browser implementation","consensus_critical":False,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"helper_receipts_certificates","current_algorithm":"helper receipt and helper certificate signing use pq-mldsa-v1 ML-DSA-65; shared-secret helper authority is removed","target_algorithm":"pq-mldsa-v1 helper receipt/certificate profile","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"local_wallet_key_storage_encryption","current_algorithm":"local storage encryption remains symmetric/local and is tracked separately from protocol signing","target_algorithm":"AEAD/symmetric local storage plus PQ recovery policy","consensus_critical":False,"account_custody":True,"observer_trust":False,"transport_or_local_only":True,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"transport_encryption_tls","current_algorithm":"TLS remains transport security; ML-KEM deployment is planned separately where libraries support it","target_algorithm":"pq-mlkem-v1 for future key establishment","consensus_critical":False,"account_custody":False,"observer_trust":False,"transport_or_local_only":True,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
]


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(path.relative_to(ROOT))


def main() -> None:
    backend_status = mldsa_backend_status()
    real_mldsa_ready = bool(backend_status.get("available") is True)
    write_json(GENERATED / "crypto_inventory_v1_5.json", {
        "schema": "weall.crypto_inventory.v1_5",
        "required_framing": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
        "active_signature_profile": PQ_MLDSA_V1,
        "classical_signature_profiles_removed": True,
        "real_mldsa_implemented_in_this_environment": real_mldsa_ready,
        "mldsa_backend_status": backend_status,
        "production_crypto_audit_complete": False,
        "surfaces": SURFACES,
    })
    write_json(GENERATED / "signature_profile_registry_v1_5.json", signature_profile_registry_json())
    write_json(GENERATED / "quantum_resistance_readiness_v1_5.json", {
        "schema": "weall.quantum_resistance_readiness.v1_5",
        "required_framing": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
        "active_signature_profile": PQ_MLDSA_V1,
        "controlled_testnet_default": PQ_MLDSA_V1,
        "classical_signature_profiles_removed": True,
        "real_mldsa_backend_required": True,
        "real_mldsa_implemented_in_this_environment": real_mldsa_ready,
        "mldsa_backend_status": backend_status,
        "production_crypto_audit_complete": False,
        "public_mainnet_ready": False,
        "public_beta_ready": False,
        "public_multi_validator_bft_ready": False,
        "live_economics": False,
        "acceptable_claim": "WeAll remains a pre-public-testnet protocol implementation under active hardening. The controlled-testnet signing profile has migrated to profile-aware ML-DSA signing for active protocol authority surfaces. This supports quantum-resistance hardening but does not claim completed production cryptographic audit, public mainnet readiness, live economics, public multi-validator BFT readiness, or production constitutional governance readiness.",
        "remaining_blockers": [
            "external cryptographic review",
            "fresh post-migration observer and validator evidence",
            "browser/client ML-DSA signing implementation or controlled signer boundary",
            "durable PQ-signed public evidence bundle policy",
        ],
    })


if __name__ == "__main__":
    main()
