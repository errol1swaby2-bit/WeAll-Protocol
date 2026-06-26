from __future__ import annotations

"""v1.5 launch-disabled feature matrix.

This module is a conservative public-readiness guardrail, not an activation
mechanism.  It centralizes which high-risk capabilities must remain disabled at
which launch phases so docs, API read models, tests, and reviewer gates do not
silently drift.

The matrix intentionally keeps live economics, treasury spending, automatic
protocol upgrades, public validator promotion, and emergency safety controls
locked for current rehearsal/public-readiness phases.  Runtime apply modules
remain the authority for actual state mutation; this module is an auditable
policy inventory and helper for fail-closed checks.
"""

from dataclasses import dataclass
from typing import Any, Mapping

Json = dict[str, Any]

PHASE_LOCAL_REHEARSAL = "local_rehearsal"
PHASE_EXTERNAL_OBSERVER = "external_observer"
PHASE_PRIVATE_VALIDATOR = "controlled_validator_rehearsal"
PHASE_PUBLIC_BETA = "public_beta_candidate"
PHASE_PRODUCTION_CANDIDATE = "production_candidate"

LAUNCH_PHASES: tuple[str, ...] = (
    PHASE_LOCAL_REHEARSAL,
    PHASE_EXTERNAL_OBSERVER,
    PHASE_PRIVATE_VALIDATOR,
    PHASE_PUBLIC_BETA,
    PHASE_PRODUCTION_CANDIDATE,
)

FEATURE_LIVE_ECONOMICS = "live_economics"
FEATURE_BALANCE_TRANSFER = "balance_transfer"
FEATURE_REWARD_ISSUANCE = "reward_issuance"
FEATURE_TREASURY_SPEND = "treasury_spend"
FEATURE_VALIDATOR_PROMOTION = "public_validator_promotion"
FEATURE_PUBLIC_BFT = "public_multi_validator_bft"
FEATURE_AUTO_PROTOCOL_UPGRADE = "automatic_protocol_upgrade_apply"
FEATURE_PROTOCOL_MIGRATION_EXECUTION = "protocol_migration_execution"
FEATURE_PROTOCOL_ROLLBACK_EXECUTION = "protocol_rollback_execution"
FEATURE_EMERGENCY_SAFETY_CONTROLS = "emergency_safety_controls"
FEATURE_HELPER_PRODUCTION_EXECUTION = "production_helper_execution"

HIGH_RISK_FEATURES: tuple[str, ...] = (
    FEATURE_LIVE_ECONOMICS,
    FEATURE_BALANCE_TRANSFER,
    FEATURE_REWARD_ISSUANCE,
    FEATURE_TREASURY_SPEND,
    FEATURE_VALIDATOR_PROMOTION,
    FEATURE_PUBLIC_BFT,
    FEATURE_AUTO_PROTOCOL_UPGRADE,
    FEATURE_PROTOCOL_MIGRATION_EXECUTION,
    FEATURE_PROTOCOL_ROLLBACK_EXECUTION,
    FEATURE_EMERGENCY_SAFETY_CONTROLS,
    FEATURE_HELPER_PRODUCTION_EXECUTION,
)

# Conservative baseline: none of these high-risk capabilities are live merely
# because code exists.  Activation requires separate gates, governance/legal
# proof, release manifests, and explicit future implementation.
_LAUNCH_DISABLED: dict[str, tuple[str, ...]] = {
    PHASE_LOCAL_REHEARSAL: HIGH_RISK_FEATURES,
    PHASE_EXTERNAL_OBSERVER: HIGH_RISK_FEATURES,
    PHASE_PRIVATE_VALIDATOR: HIGH_RISK_FEATURES,
    PHASE_PUBLIC_BETA: HIGH_RISK_FEATURES,
    PHASE_PRODUCTION_CANDIDATE: HIGH_RISK_FEATURES,
}

_FEATURE_REASONS: dict[str, str] = {
    FEATURE_LIVE_ECONOMICS: "Live economics requires lock expiry, governance activation, legal/compliance review, accounting proof, and public testnet rehearsal.",
    FEATURE_BALANCE_TRANSFER: "Transfers are implemented but locked until economics activation is canonical and public claims are safe.",
    FEATURE_REWARD_ISSUANCE: "Issuance policy is implemented, but live rewards remain locked until economics activation and accounting proof.",
    FEATURE_TREASURY_SPEND: "Treasury spending requires economics activation and treasury governance/public accountability proof.",
    FEATURE_VALIDATOR_PROMOTION: "Public validator promotion requires separate external multi-validator proof and operator readiness gates.",
    FEATURE_PUBLIC_BFT: "Public multi-validator BFT requires adversarial convergence, churn, partition/rejoin, equivocation, and restart/replay evidence.",
    FEATURE_AUTO_PROTOCOL_UPGRADE: "Protocol upgrades are record-only until signed artifact distribution, staging, migration, and rollback are implemented.",
    FEATURE_PROTOCOL_MIGRATION_EXECUTION: "Migrations must not execute from upgrade records without deterministic vector tests and release manifests.",
    FEATURE_PROTOCOL_ROLLBACK_EXECUTION: "Rollback execution requires deterministic rollback semantics and artifact verification; it is not live.",
    FEATURE_EMERGENCY_SAFETY_CONTROLS: "Emergency controls require legal/governance authority, auditability, and public policy before exposure.",
    FEATURE_HELPER_PRODUCTION_EXECUTION: "Production helper execution requires serial-equivalence and multi-node Byzantine helper tests.",
}


@dataclass(frozen=True, slots=True)
class LaunchFeatureStatus:
    phase: str
    feature: str
    enabled: bool
    disabled_reason: str
    truth_boundary: str

    def as_dict(self) -> Json:
        return {
            "phase": self.phase,
            "feature": self.feature,
            "enabled": bool(self.enabled),
            "disabled_reason": self.disabled_reason,
            "truth_boundary": self.truth_boundary,
        }


def normalize_launch_phase(phase: str | None) -> str:
    value = str(phase or "").strip().lower().replace("-", "_")
    aliases = {
        "dev": PHASE_LOCAL_REHEARSAL,
        "local": PHASE_LOCAL_REHEARSAL,
        "observer": PHASE_EXTERNAL_OBSERVER,
        "external": PHASE_EXTERNAL_OBSERVER,
        "controlled_validator": PHASE_PRIVATE_VALIDATOR,
        "controlled_devnet": PHASE_PRIVATE_VALIDATOR,
        "testnet": PHASE_PUBLIC_BETA,
        "public_beta": PHASE_PUBLIC_BETA,
        "prod": PHASE_PRODUCTION_CANDIDATE,
        "production": PHASE_PRODUCTION_CANDIDATE,
    }
    value = aliases.get(value, value)
    if value not in LAUNCH_PHASES:
        return PHASE_LOCAL_REHEARSAL
    return value


def feature_status(phase: str | None, feature: str) -> LaunchFeatureStatus:
    normalized = normalize_launch_phase(phase)
    f = str(feature or "").strip()
    disabled = f in set(_LAUNCH_DISABLED.get(normalized, ()))
    return LaunchFeatureStatus(
        phase=normalized,
        feature=f,
        enabled=not disabled,
        disabled_reason=_FEATURE_REASONS.get(f, "") if disabled else "",
        truth_boundary="Launch matrix is a conservative guardrail; runtime apply/admission code remains authoritative.",
    )


def is_feature_enabled(phase: str | None, feature: str) -> bool:
    return feature_status(phase, feature).enabled


def launch_matrix_payload() -> Json:
    rows: list[Json] = []
    for phase in LAUNCH_PHASES:
        for feature in HIGH_RISK_FEATURES:
            rows.append(feature_status(phase, feature).as_dict())
    return {
        "schema": "weall.launch_disabled_matrix.v1_5",
        "version": "2026-06-v1.5-public-readiness-batch",
        "phases": list(LAUNCH_PHASES),
        "high_risk_features": list(HIGH_RISK_FEATURES),
        "rows": rows,
        "truth_boundary": "This matrix prevents overclaims and drift; it does not activate or disable consensus rules by itself.",
    }


def assert_feature_disabled(phase: str | None, feature: str) -> None:
    status = feature_status(phase, feature)
    if status.enabled:
        raise ValueError(f"feature_enabled:{status.phase}:{feature}")


def disabled_features_for_phase(phase: str | None) -> tuple[str, ...]:
    normalized = normalize_launch_phase(phase)
    return tuple(_LAUNCH_DISABLED.get(normalized, ()))


def launch_matrix_from_state(state: Mapping[str, Any] | None) -> Json:
    st = state if isinstance(state, Mapping) else {}
    params = st.get("params") if isinstance(st.get("params"), Mapping) else {}
    phase = str(params.get("launch_phase") or params.get("network_phase") or st.get("mode") or "").strip()
    normalized = normalize_launch_phase(phase)
    return {
        "phase": normalized,
        "disabled_features": list(disabled_features_for_phase(normalized)),
        "feature_status": {feature: feature_status(normalized, feature).as_dict() for feature in HIGH_RISK_FEATURES},
    }


__all__ = [
    "FEATURE_AUTO_PROTOCOL_UPGRADE",
    "FEATURE_BALANCE_TRANSFER",
    "FEATURE_EMERGENCY_SAFETY_CONTROLS",
    "FEATURE_HELPER_PRODUCTION_EXECUTION",
    "FEATURE_LIVE_ECONOMICS",
    "FEATURE_PROTOCOL_MIGRATION_EXECUTION",
    "FEATURE_PROTOCOL_ROLLBACK_EXECUTION",
    "FEATURE_PUBLIC_BFT",
    "FEATURE_REWARD_ISSUANCE",
    "FEATURE_TREASURY_SPEND",
    "FEATURE_VALIDATOR_PROMOTION",
    "HIGH_RISK_FEATURES",
    "LAUNCH_PHASES",
    "assert_feature_disabled",
    "disabled_features_for_phase",
    "feature_status",
    "is_feature_enabled",
    "launch_matrix_from_state",
    "launch_matrix_payload",
    "normalize_launch_phase",
]
