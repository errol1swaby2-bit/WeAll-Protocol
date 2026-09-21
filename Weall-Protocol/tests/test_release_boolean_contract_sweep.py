from __future__ import annotations

import re
from pathlib import Path

import gen_b582_b586_readiness_truth_and_proof_v1_5 as b582
import gen_b587_b594_testnet_mechanism_completion_v1_5 as b587
from run_controlled_testnet_go_gate_v1_5 import _summarize_b587

ROOT = Path(__file__).resolve().parents[1]


def test_controlled_gate_b587_summary_rejects_truthy_strings() -> None:
    summary = _summarize_b587(
        {
            "ok": "true",
            "controlled_testnet_mechanisms_complete": "true",
            "controlled_testnet_ready_candidate": "true",
            "public_beta_ready": "true",
            "claim_boundaries": {
                "live_economics": False,
                "public_validator_readiness": False,
                "production_helper_execution": False,
                "automatic_protocol_upgrades": False,
            },
        }
    )
    assert summary["ok"] is False
    assert summary["controlled_testnet_mechanisms_complete"] is False
    assert summary["controlled_testnet_ready_candidate"] is False
    assert summary["public_beta_ready"] is False


def test_b582_component_ok_requires_exact_boolean(monkeypatch) -> None:
    monkeypatch.setattr(b582, "_gap_register_truth", lambda: {"ok": True})
    monkeypatch.setattr(b582, "_operator_route_metadata_truth", lambda: {"ok": True})
    monkeypatch.setattr(b582, "run_storage_durability", lambda: {"ok": "true"})
    monkeypatch.setattr(b582, "run_anti_sybil_lifecycle", lambda: {"ok": True})
    monkeypatch.setattr(b582, "run_helper_corpus", lambda: {"ok": True})
    assert b582.build()["ok"] is False


def test_b587_component_ok_requires_exact_boolean(monkeypatch) -> None:
    capability_map = {
        key: {"enabled": False}
        for key in (
            "live_transfers",
            "live_rewards",
            "treasury_spend",
            "live_economics",
            "public_validator_join",
            "public_multi_validator_bft",
            "automatic_protocol_upgrade_apply",
            "production_helper_execution",
        )
    }
    monkeypatch.setattr(
        b587,
        "build_testnet_capability_surface",
        lambda state: {
            "capabilities": capability_map,
            "required_artifacts": {},
            "artifact_blockers": [],
            "controlled_mechanism_artifact_blockers": [],
            "public_beta_blocker_report": {"present": True, "ok": True},
        },
    )
    monkeypatch.setattr(b587, "build_api_response_vectors", lambda: {"ok": True})
    monkeypatch.setattr(b587, "run_upgrade_staging", lambda: {"ok": True})
    monkeypatch.setattr(b587, "run_validator_harness", lambda: {"ok": "true"})
    monkeypatch.setattr(b587, "run_storage_harness", lambda: {"ok": True})
    monkeypatch.setattr(b587, "run_reviewer_accountability", lambda: {"ok": True})
    monkeypatch.setattr(
        b587,
        "run_helper_block_path",
        lambda: {
            "ok": True,
            "production_block_path_state_root_equivalence_proven": True,
            "mechanism_complete": True,
        },
    )
    monkeypatch.setattr(b587, "run_locked_economics", lambda: {"ok": True})
    result = b587.build()
    assert result["component_harnesses_ok"] is False
    assert result["ok"] is False


def test_release_critical_sources_have_no_bool_wrapped_ok_or_default_true_ok() -> None:
    files = [
        "scripts/gen_public_beta_blocker_report_v1_5.py",
        "scripts/gen_b582_b586_readiness_truth_and_proof_v1_5.py",
        "scripts/gen_b587_b594_testnet_mechanism_completion_v1_5.py",
        "scripts/run_controlled_testnet_go_gate_v1_5.py",
        "scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py",
        "scripts/gen_release_evidence_manifest_v1_5.py",
        "scripts/rehearse_public_api_write_lifecycle_v1_5.py",
    ]
    wrapped_ok = re.compile(
        r'bool\(\s*[A-Za-z_][A-Za-z0-9_]*\.get\("ok"\)\s*\)',
        re.MULTILINE,
    )
    for rel in files:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert not wrapped_ok.search(text), rel
        assert '.get("ok", True)' not in text, rel


def test_release_artifact_check_mode_is_freshness_only() -> None:
    targets = (
        "scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py",
        "scripts/gen_release_evidence_manifest_v1_5.py",
    )
    for rel in targets:
        source = (ROOT / rel).read_text(encoding="utf-8")
        check_block = source.split("if args.check:", 1)[1].split("OUT.parent.mkdir", 1)[0]
        assert "return 0" in check_block
        assert 'return 0 if payload.get("ok")' not in check_block
