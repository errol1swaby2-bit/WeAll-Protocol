from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.launch_matrix import FEATURE_HELPER_PRODUCTION_EXECUTION, LAUNCH_PHASES, feature_status

ROOT = Path(__file__).resolve().parents[2]


def test_production_helper_topology_hardening_plan_artifact_is_fresh_and_open() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_production_helper_topology_hardening_plan_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "production_helper_topology_hardening_plan_v1_5.json").read_text(encoding="utf-8"))
    assert payload["blocker"] == "AUD-618-P1-005"
    assert payload["blocker_status"] == "open_future_mainnet_hardening"
    assert payload["production_helper_execution_enabled"] is False
    assert payload["production_helper_execution_ready"] is False
    assert payload["public_beta_ready"] is False
    assert payload["mainnet_ready"] is False
    assert payload["current_boundary"]["launch_matrix_blocks_all_current_phases"] is True
    assert payload["current_boundary"]["missing_helpers_can_halt_block_production"] is False
    assert payload["current_boundary"]["serial_fallback_required"] is True
    assert payload["claim_boundaries"]["production_helper_execution"] is False
    assert payload["claim_boundaries"]["helper_mode_authority"] is False
    assert "serial_vs_helper_equivalence_corpus_for_all_supported_tx_types" in payload["future_required_evidence"]
    assert "byzantine_helper_output_rejection_and_misbehavior_proof" in payload["future_required_evidence"]
    assert "governance_release_gate_with_launch_matrix_transition" in payload["future_required_evidence"]


def test_production_helper_topology_docs_and_template_preserve_non_claims() -> None:
    docs = [
        ROOT / "docs" / "testnet" / "PRODUCTION_HELPER_TOPOLOGY_HARDENING_PLAN.md",
        ROOT / "docs" / "proofs" / "production-helper-topology-hardening" / "2026-07-05" / "README.md",
    ]
    for path in docs:
        text = path.read_text(encoding="utf-8").lower()
        assert "aud-618-p1-005" in text
        assert "disabled" in text
        assert "serial" in text
        assert "byzantine" in text
        assert "governance/release" in text
        assert "public beta" in text or "public-beta" in text
    template = json.loads((ROOT / "docs" / "proofs" / "production-helper-topology-hardening" / "2026-07-05" / "PLAN_TEMPLATE.json").read_text(encoding="utf-8"))
    assert template["template_only"] is True
    assert template["external_topology_evidence_attached"] is False
    assert template["production_helper_execution_enabled"] is False
    assert template["current_disabled_boundary"]["launch_matrix_blocks_production_helper_execution"] is True
    assert template["current_disabled_boundary"]["local_script_authority"] is False
    assert template["current_disabled_boundary"]["missing_helpers_halt_block_production"] is False
    assert template["claim_boundaries"]["production_helper_execution"] is False


def test_launch_matrix_keeps_production_helper_execution_disabled_in_all_current_phases() -> None:
    for phase in LAUNCH_PHASES:
        status = feature_status(phase, FEATURE_HELPER_PRODUCTION_EXECUTION)
        assert status.enabled is False
        assert "serial-equivalence" in status.disabled_reason
        assert "guardrail" in status.truth_boundary


def test_public_beta_report_references_helper_topology_hardening_plan() -> None:
    payload = json.loads((ROOT / "generated" / "public_beta_blocker_report_v1_5.json").read_text(encoding="utf-8"))
    by_id = {row["id"]: row for row in payload["blockers"]}
    blocker = by_id["AUD-618-P1-005"]
    assert blocker["gate_status"] == "hardening_plan_present_execution_still_disabled"
    assert blocker["evidence_gate"] == "production_helper_topology_hardening_plan"
    assert "multi-node helper topology transcript" in blocker["remaining_external_evidence"]
    helper_plan = payload["evidence_gate_summaries"]["production_helper_topology_hardening_plan"]
    assert helper_plan["ok"] is True
    assert helper_plan["blocker"] == "AUD-618-P1-005"
    assert helper_plan["production_helper_execution_enabled"] is False
    assert helper_plan["production_helper_execution_ready"] is False


def test_release_manifest_tracks_helper_topology_hardening_gate() -> None:
    payload = json.loads((ROOT / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8"))
    artifacts = payload["tracked_artifacts"]
    assert "generated/production_helper_topology_hardening_plan_v1_5.json" in artifacts
    gate = payload["release_evidence_gates"]["production_helper_topology_hardening_plan"]
    assert gate["blocker"] == "AUD-618-P1-005"
    assert gate["current_execution_enabled"] is False
    assert gate["keeps_launch_matrix_disabled"] is True
    assert gate["future_governance_release_gate_required"] is True
