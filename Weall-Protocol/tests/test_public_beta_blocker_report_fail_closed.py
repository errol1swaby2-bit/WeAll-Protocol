from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "gen_public_beta_blocker_report_v1_5.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "gen_public_beta_blocker_report_under_test",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_external_evidence_disposition_tracks_actual_blocked_surface() -> None:
    module = _load_module()
    result = module._classify_blocker(
        severity="P1",
        blocks=["public_observer_launch"],
        gate_status="gate_present_external_transcript_required",
        remaining_external_evidence=["external observer transcript"],
        can_be_closed_by_code_only=False,
    )
    assert result["blocker_category"] == "external_evidence_required"
    assert result["release_disposition"] == "keep_open_for_public_observer_launch_external_evidence"
    assert result["safe_to_close_with_current_repository_evidence"] is False
    assert result["safe_to_reduce_with_current_evidence"] is False


def test_external_evidence_disposition_handles_multiple_blocked_surfaces() -> None:
    module = _load_module()
    result = module._classify_blocker(
        severity="P0",
        blocks=["public_beta", "mainnet"],
        gate_status="gate_present_external_attestation_required",
        remaining_external_evidence=["operator-signed transcript"],
        can_be_closed_by_code_only=False,
    )
    assert (
        result["release_disposition"] == "keep_open_for_public_beta_and_mainnet_external_evidence"
    )


def test_closed_gate_remains_closed() -> None:
    module = _load_module()
    result = module._classify_blocker(
        severity="P1",
        blocks=["public_beta"],
        gate_status="closed_as_artifact_gate",
        remaining_external_evidence=[],
        can_be_closed_by_code_only=True,
    )
    assert result["blocker_category"] == "closed_by_artifact_or_docs"
    assert result["release_disposition"] == "closed_in_repository"
    assert result["safe_to_close_with_current_repository_evidence"] is True


def test_failed_gate_without_external_evidence_is_not_classified_closed() -> None:
    module = _load_module()
    result = module._classify_blocker(
        severity="P1",
        blocks=["public_beta"],
        gate_status="gate_failed",
        remaining_external_evidence=[],
        can_be_closed_by_code_only=True,
    )
    assert result["blocker_category"] == "code_or_test_hardening"
    assert result["safe_to_close_with_current_repository_evidence"] is False


def test_needs_more_vectors_without_external_evidence_is_not_classified_closed() -> None:
    module = _load_module()
    result = module._classify_blocker(
        severity="P1",
        blocks=["public_beta"],
        gate_status="needs_more_vectors",
        remaining_external_evidence=[],
        can_be_closed_by_code_only=True,
    )
    assert result["blocker_category"] == "code_or_test_hardening"
    assert result["safe_to_close_with_current_repository_evidence"] is False
