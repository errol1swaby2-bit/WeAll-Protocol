from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.launch_matrix import (
    FEATURE_AUTO_PROTOCOL_UPGRADE,
    FEATURE_EMERGENCY_SAFETY_CONTROLS,
    FEATURE_LIVE_ECONOMICS,
    FEATURE_PUBLIC_BFT,
    FEATURE_TREASURY_SPEND,
    FEATURE_VALIDATOR_PROMOTION,
    HIGH_RISK_FEATURES,
    LAUNCH_PHASES,
    disabled_features_for_phase,
    feature_status,
    launch_matrix_from_state,
    launch_matrix_payload,
    normalize_launch_phase,
)

ROOT = Path(__file__).resolve().parents[1]


def test_launch_matrix_disables_high_risk_features_for_current_phases_batch495() -> None:
    required = {
        FEATURE_LIVE_ECONOMICS,
        FEATURE_TREASURY_SPEND,
        FEATURE_VALIDATOR_PROMOTION,
        FEATURE_PUBLIC_BFT,
        FEATURE_AUTO_PROTOCOL_UPGRADE,
        FEATURE_EMERGENCY_SAFETY_CONTROLS,
    }
    for phase in LAUNCH_PHASES:
        disabled = set(disabled_features_for_phase(phase))
        assert required.issubset(disabled)
        for feature in required:
            status = feature_status(phase, feature)
            assert status.enabled is False
            assert status.disabled_reason
            assert "runtime apply" in status.truth_boundary.lower()


def test_launch_matrix_generated_artifact_matches_runtime_batch495() -> None:
    artifact = json.loads((ROOT / "generated/launch_disabled_matrix_v1_5.json").read_text(encoding="utf-8"))
    runtime = launch_matrix_payload()
    assert artifact == runtime
    assert len(artifact["rows"]) == len(LAUNCH_PHASES) * len(HIGH_RISK_FEATURES)


def test_launch_matrix_aliases_and_state_read_model_batch495() -> None:
    assert normalize_launch_phase("prod") == "production_candidate"
    assert normalize_launch_phase("testnet") == "public_beta_candidate"
    assert normalize_launch_phase("controlled_devnet") == "private_validator_rehearsal"

    status = launch_matrix_from_state({"params": {"launch_phase": "public_beta"}})
    assert status["phase"] == "public_beta_candidate"
    assert FEATURE_LIVE_ECONOMICS in status["disabled_features"]
    assert status["feature_status"][FEATURE_AUTO_PROTOCOL_UPGRADE]["enabled"] is False
