from __future__ import annotations

"""Deterministic post-quantum signature/key-establishment profile registry.

WeAll no longer carries a classical signature profile in active protocol code.
All executable authority surfaces are expected to declare and verify
``pq-mldsa-v1`` for signatures.  ``pq-mlkem-v1`` remains key establishment /
transport only, and ``pq-slhdsa-v1`` remains a reserved backup-signature track.
Unknown or classical profiles fail closed.
"""

import os
from dataclasses import asdict, dataclass
from typing import Any

PQ_MLDSA_V1 = "pq-mldsa-v1"
PQ_SLHDSA_V1 = "pq-slhdsa-v1"
PQ_MLKEM_V1 = "pq-mlkem-v1"

SIGNING_PURPOSES = {"signing", "backup_signature"}
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
            notes="Sole active WeAll protocol signing profile. Requires external cryptographic review before mainnet.",
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
        "active_signature_profile": PQ_MLDSA_V1,
        "future_backup_signature_profile": PQ_SLHDSA_V1,
        "transport_key_establishment_profile": PQ_MLKEM_V1,
        "fail_closed_unknown_profiles": True,
        "classical_signature_profiles_removed": True,
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
    # After the PQ-only transition, all executable signing surfaces require an
    # explicit profile unless a caller is constructing a new object through the
    # central signing helper, which stamps pq-mldsa-v1.
    return True


def default_signature_profile_for_mode(mode: str | None = None) -> str:
    return PQ_MLDSA_V1


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


def allowed_signature_profiles_for_mode(
    *,
    mode: str | None = None,
    chain_config: dict[str, Any] | None = None,
) -> set[str]:
    allowlist = {p for p in _chain_allowlist(chain_config) if p in signature_profile_registry()}
    if allowlist:
        return allowlist
    return {PQ_MLDSA_V1}


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
    if require_verifier and purpose == "signing" and not profile.verifier_available:
        return False, "signature_profile_verifier_unavailable"
    return True, "ok"


def profile_metadata(profile_id: Any) -> dict[str, Any]:
    profile = get_signature_profile(profile_id)
    return profile.to_json() if profile else {"profile_id": normalize_signature_profile_id(profile_id), "known": False}
