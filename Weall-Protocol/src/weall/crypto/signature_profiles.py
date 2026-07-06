from __future__ import annotations

"""Deterministic signature/key-establishment profile registry.

This module is intentionally policy-only.  It does not implement cryptography;
callers must route signing/verification through the appropriate verifier and
fail closed when the verifier for an allowed profile is unavailable.
"""

import os
from dataclasses import asdict, dataclass
from typing import Any

LEGACY_ED25519_V1 = "legacy-ed25519-v1"
PQ_MLDSA_V1 = "pq-mldsa-v1"
PQ_SLHDSA_V1 = "pq-slhdsa-v1"
PQ_MLKEM_V1 = "pq-mlkem-v1"

SIGNING_PURPOSES = {"signing", "backup_signature", "legacy"}
STRICT_TESTNET_MODES = {"closed-testnet", "closed_testnet", "controlled-testnet", "controlled_testnet", "public-testnet", "public_testnet"}
LOCAL_MODES = {"dev", "local", "test", "ci", "demo", "controlled_devnet", "controlled-devnet"}


@dataclass(frozen=True, slots=True)
class SignatureProfile:
    profile_id: str
    algorithm_family: str
    purpose: str
    status: str
    post_quantum: bool
    allowed_in_dev_local: bool
    allowed_in_closed_testnet: bool
    allowed_in_public_testnet: bool
    allowed_in_mainnet: bool
    verifier_available: bool
    activation_height_support: bool
    chain_config_allowlist_support: bool
    notes: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _detect_mldsa_verifier_available() -> bool:
    try:
        from weall.crypto.pq_mldsa import mldsa_backend_status

        return bool(mldsa_backend_status().get("available") is True)
    except Exception:
        return False


def _profiles() -> dict[str, SignatureProfile]:
    return {
        LEGACY_ED25519_V1: SignatureProfile(
            profile_id=LEGACY_ED25519_V1,
            algorithm_family="Ed25519",
            purpose="legacy",
            status="legacy",
            post_quantum=False,
            allowed_in_dev_local=True,
            allowed_in_closed_testnet=False,
            allowed_in_public_testnet=False,
            allowed_in_mainnet=False,
            verifier_available=True,
            activation_height_support=True,
            chain_config_allowlist_support=True,
            notes="Classical-only signature profile. Dev/local and explicit migration tests only.",
        ),
        PQ_MLDSA_V1: SignatureProfile(
            profile_id=PQ_MLDSA_V1,
            algorithm_family="ML-DSA-65/FIPS-204",
            purpose="signing",
            status="active",
            post_quantum=True,
            allowed_in_dev_local=True,
            allowed_in_closed_testnet=True,
            allowed_in_public_testnet=True,
            allowed_in_mainnet=False,
            verifier_available=_detect_mldsa_verifier_available(),
            activation_height_support=True,
            chain_config_allowlist_support=True,
            notes="Controlled-testnet target signing profile. Requires external cryptographic review before mainnet.",
        ),
        PQ_SLHDSA_V1: SignatureProfile(
            profile_id=PQ_SLHDSA_V1,
            algorithm_family="SLH-DSA/FIPS-205",
            purpose="backup_signature",
            status="reserved",
            post_quantum=True,
            allowed_in_dev_local=False,
            allowed_in_closed_testnet=False,
            allowed_in_public_testnet=False,
            allowed_in_mainnet=False,
            verifier_available=False,
            activation_height_support=True,
            chain_config_allowlist_support=True,
            notes="Reserved backup signature profile; not accepted by runtime admission.",
        ),
        PQ_MLKEM_V1: SignatureProfile(
            profile_id=PQ_MLKEM_V1,
            algorithm_family="ML-KEM/FIPS-203",
            purpose="key_establishment",
            status="reserved",
            post_quantum=True,
            allowed_in_dev_local=False,
            allowed_in_closed_testnet=False,
            allowed_in_public_testnet=False,
            allowed_in_mainnet=False,
            verifier_available=False,
            activation_height_support=False,
            chain_config_allowlist_support=True,
            notes="Key-establishment/transport only. Must not be used for transaction signing.",
        ),
    }


def signature_profile_registry() -> dict[str, SignatureProfile]:
    return dict(_profiles())


def signature_profile_registry_json() -> dict[str, Any]:
    profiles = [p.to_json() for p in signature_profile_registry().values()]
    return {
        "schema": "weall.signature_profile_registry.v1_5",
        "default_controlled_testnet_signature_profile": PQ_MLDSA_V1,
        "legacy_profile": LEGACY_ED25519_V1,
        "future_backup_signature_profile": PQ_SLHDSA_V1,
        "transport_key_establishment_profile": PQ_MLKEM_V1,
        "fail_closed_unknown_profiles": True,
        "silent_ed25519_fallback_allowed": False,
        "production_crypto_audit_complete": False,
        "profiles": profiles,
    }


def normalize_signature_profile_id(value: Any) -> str:
    return str(value or "").strip().lower()


def get_signature_profile(profile_id: Any) -> SignatureProfile | None:
    return signature_profile_registry().get(normalize_signature_profile_id(profile_id))


def require_signature_profile(profile_id: Any) -> SignatureProfile:
    profile = get_signature_profile(profile_id)
    if profile is None:
        raise ValueError("unknown_signature_profile")
    return profile


def runtime_crypto_mode() -> str:
    explicit = str(os.environ.get("WEALL_CRYPTO_MODE") or "").strip().lower()
    if explicit:
        return explicit
    if str(os.environ.get("WEALL_PUBLIC_TESTNET") or "").strip().lower() in {"1", "true", "yes", "on"}:
        return "public-testnet"
    return str(os.environ.get("WEALL_MODE") or "prod").strip().lower() or "prod"


def mode_requires_explicit_sig_profile(mode: str | None = None) -> bool:
    m = (mode or runtime_crypto_mode()).strip().lower()
    return m in STRICT_TESTNET_MODES or str(os.environ.get("WEALL_REQUIRE_SIGNATURE_PROFILES") or "").strip().lower() in {"1", "true", "yes", "on"}


def default_signature_profile_for_mode(mode: str | None = None) -> str:
    m = (mode or runtime_crypto_mode()).strip().lower()
    if m in STRICT_TESTNET_MODES or m in {"testnet"}:
        return PQ_MLDSA_V1
    return LEGACY_ED25519_V1


def _chain_crypto_config(chain_config: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(chain_config, dict):
        return {}
    raw = chain_config.get("crypto") or chain_config.get("signature_profiles") or {}
    return raw if isinstance(raw, dict) else {}


def _chain_allowlist(chain_config: dict[str, Any] | None) -> list[str]:
    crypto = _chain_crypto_config(chain_config)
    raw = crypto.get("allowed_signature_profiles") or crypto.get("allowed_profiles")
    if isinstance(raw, list):
        return [normalize_signature_profile_id(x) for x in raw if normalize_signature_profile_id(x)]
    return []


def legacy_ed25519_explicitly_allowed(chain_config: dict[str, Any] | None = None) -> bool:
    crypto = _chain_crypto_config(chain_config)
    if crypto.get("allow_legacy_ed25519") is True:
        return True
    return LEGACY_ED25519_V1 in _chain_allowlist(chain_config)


def allowed_signature_profiles_for_mode(
    *,
    mode: str | None = None,
    chain_config: dict[str, Any] | None = None,
) -> set[str]:
    allowlist = set(_chain_allowlist(chain_config))
    if allowlist:
        # Unknown allowlist entries do not become valid profiles; fail closed later.
        return allowlist
    m = (mode or runtime_crypto_mode()).strip().lower()
    if m in STRICT_TESTNET_MODES:
        return {PQ_MLDSA_V1}
    if m in {"mainnet"}:
        return set()
    if m in LOCAL_MODES or m in {"testnet"}:
        return {LEGACY_ED25519_V1, PQ_MLDSA_V1}
    # Production service manifests are not public/mainnet claims. Keep Ed25519
    # migration compatibility unless strict testnet mode is explicitly selected.
    return {LEGACY_ED25519_V1, PQ_MLDSA_V1}


def profile_allowed_for_context(
    profile_id: Any,
    *,
    purpose: str = "signing",
    mode: str | None = None,
    chain_config: dict[str, Any] | None = None,
    require_verifier: bool = True,
) -> tuple[bool, str]:
    normalized = normalize_signature_profile_id(profile_id)
    profile = get_signature_profile(normalized)
    if profile is None:
        return False, "unknown_signature_profile"
    if purpose == "signing" and profile.purpose not in SIGNING_PURPOSES:
        return False, "signature_profile_wrong_purpose"
    allowed = allowed_signature_profiles_for_mode(mode=mode, chain_config=chain_config)
    if normalized not in allowed:
        return False, "signature_profile_not_allowed"
    if normalized == LEGACY_ED25519_V1:
        m = (mode or runtime_crypto_mode()).strip().lower()
        if m in STRICT_TESTNET_MODES and not legacy_ed25519_explicitly_allowed(chain_config):
            return False, "legacy_ed25519_not_allowed"
    if require_verifier and purpose == "signing" and not profile.verifier_available:
        return False, "signature_profile_verifier_unavailable"
    return True, "ok"


def profile_metadata(profile_id: Any) -> dict[str, Any]:
    profile = get_signature_profile(profile_id)
    return profile.to_json() if profile else {"profile_id": normalize_signature_profile_id(profile_id), "known": False}
