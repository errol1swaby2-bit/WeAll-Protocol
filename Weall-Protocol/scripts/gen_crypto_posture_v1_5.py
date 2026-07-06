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
    {"surface":"transaction_signatures","current_algorithm":"profile-aware pq-mldsa-v1 signing/verifying through pyca/cryptography ML-DSA-65; legacy-ed25519-v1 remains dev/migration only when explicitly allowed","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"account_keys","current_algorithm":"profile-aware account key records create pq-mldsa-v1 mldsa pubkeys for registration/key-add/recovery paths; legacy classical records are migration/dev-only","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"account_recovery_keys","current_algorithm":"profile-aware recovery key records are supported and default to pq-mldsa-v1 in controlled/public testnet modes","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"session_login_signatures","current_algorithm":"browser/API session-login proofs are profile-aware; controlled/public testnet mode rejects missing profiles and accepts pq-mldsa-v1 proofs over chain/network-bound canonical login payloads","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"validator_operator_signatures","current_algorithm":"validator/operator records and HotStuff vote/timeout/proposal signing are profile-aware and support pq-mldsa-v1 ML-DSA-65","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"block_signatures","current_algorithm":"block signature profile admission requires verifier availability and rejects unknown/disallowed profiles","target_algorithm":"pq-mldsa-v1","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"bft_qc_signatures","current_algorithm":"HotStuff vote, timeout, proposal, and QC verification paths are profile-aware and covered by real ML-DSA-65 tests; public multi-validator BFT readiness remains unclaimed pending external/operator evidence","target_algorithm":"pq-mldsa-v1 or externally reviewed threshold/aggregate profile","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"seed_registry_signatures","current_algorithm":"checked-in public testnet seed registry is pq-mldsa-v1/ML-DSA-65 signed and pinned to pq-mldsa-v1 trust roots","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"public_testnet_trust_roots","current_algorithm":"trust roots allow pq-mldsa-v1 for public testnet registry verification and keep legacy Ed25519 transitional/dev-only","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"validator_endpoint_advertisements","current_algorithm":"registry signing script signs validator endpoint advertisements as pq-mldsa-v1 by default with explicit legacy override only","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"peer_identity_signatures","current_algorithm":"PEER_HELLO identity proofs are profile-aware and support pq-mldsa-v1 ML-DSA-65; legacy V1/V2 Ed25519 remains migration fallback","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"gossip_signatures","current_algorithm":"signed peer address gossip records are profile-aware and support pq-mldsa-v1 ML-DSA-65","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"relay_signatures","current_algorithm":"relay access requests and relay envelopes are profile-aware and support pq-mldsa-v1 ML-DSA-65","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"observer_onboarding_signatures","current_algorithm":"observer onboarding consumes pq-mldsa-v1 registry trust roots; any remaining local evidence signatures remain non-authoritative until migrated","target_algorithm":"pq-mldsa-v1","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"evidence_bundle_signatures_digests","current_algorithm":"SHA-256 digests remain for evidence integrity; durable signed evidence bundles still require pq-mldsa-v1 signing policy","target_algorithm":"pq-mldsa-v1 signatures plus documented digest policy","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"frontend_signing_assumptions","current_algorithm":"observer UI exposes active pq-mldsa-v1 crypto profile; browser-local Ed25519 helper is explicitly legacy/dev-only pending browser ML-DSA support","target_algorithm":"pq-mldsa-v1 or controlled backend/operator signer","consensus_critical":False,"account_custody":True,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"helper_receipts_certificates","current_algorithm":"helper receipt and helper certificate signing are profile-aware and support pq-mldsa-v1 ML-DSA-65; HMAC and Ed25519 compatibility remain legacy/dev-only while production helper execution stays separately disabled","target_algorithm":"pq-mldsa-v1 helper receipt/certificate profile","consensus_critical":True,"account_custody":False,"observer_trust":True,"transport_or_local_only":False,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
    {"surface":"local_wallet_key_storage_encryption","current_algorithm":"symmetric/local storage varies and is documented separately from PQ signing migration","target_algorithm":"AES-256-equivalent plus PQ-aware backup plan","consensus_critical":False,"account_custody":True,"observer_trust":False,"transport_or_local_only":True,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":True,"external_audit_before_mainnet":True},
    {"surface":"transport_tls_assumptions","current_algorithm":"conventional TLS stack; pq-mlkem-v1 remains a documented future key-establishment target rather than transaction signing profile","target_algorithm":"TLS plus future pq-mlkem-v1/hybrid support where available","consensus_critical":False,"account_custody":False,"observer_trust":True,"transport_or_local_only":True,"upgrade_before_closed_testnet":False,"upgrade_before_public_testnet":False,"external_audit_before_mainnet":True},
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
        "frontend_local_pq_signing_not_complete",
        "public_evidence_bundle_pq_signing_policy_missing",
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
        "acceptable_claim": "WeAll remains a pre-public-testnet protocol implementation under active hardening. The controlled-testnet signing profile has transitioned from classical-only Ed25519 to profile-aware ML-DSA signing for protocol authority surfaces covered by this pass. This supports quantum-resistance hardening but does not claim completed production cryptographic audit, public mainnet readiness, live economics, public multi-validator BFT readiness, or production constitutional governance readiness.",
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
