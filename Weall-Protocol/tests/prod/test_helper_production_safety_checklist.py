from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "reviewer" / "HELPER_PRODUCTION_SAFETY_CHECKLIST.md"


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected file: {path}"
    return path.read_text(encoding="utf-8")


def test_helper_production_safety_checklist_covers_required_topics_and_non_claims() -> None:
    text = _read(DOC).lower()
    for topic in (
        "deterministic assignment",
        "lane partitioning",
        "canonical ordering",
        "deterministic receipts",
        "merge behavior",
        "crash safety",
        "byzantine/malformed result rejection",
        "serial equivalence",
        "helper execution root binding",
        "replay behavior",
        "fail-closed invalid metadata",
    ):
        assert topic in text

    for non_claim in (
        "production helper execution is not enabled",
        "helper mode does not grant protocol authority",
        "missing helpers must not halt block production",
        "public beta/mainnet readiness cannot be inferred",
    ):
        assert non_claim in text


def test_helper_safety_checklist_points_to_real_targeted_tests() -> None:
    text = _read(DOC)
    for rel in (
        "tests/test_helper_restart_equivalence.py",
        "tests/test_helper_replay_guard.py",
        "tests/test_helper_replay_guard_plan_binding.py",
        "tests/test_helper_replay_merge_adversarial.py",
        "tests/test_helper_store_conflict_timeout_recovery.py",
        "tests/test_protocol_blocker_safety.py",
        "tests/prod/test_production_helper_topology_hardening_plan.py",
    ):
        assert rel in text
        assert (ROOT / rel).exists(), f"documented helper safety test missing: {rel}"


def test_helper_generated_plan_and_checklist_agree_production_execution_disabled() -> None:
    payload = json.loads(_read(ROOT / "generated" / "production_helper_topology_hardening_plan_v1_5.json"))
    assert payload["production_helper_execution_enabled"] is False
    assert payload["production_helper_execution_ready"] is False
    assert payload["current_boundary"]["serial_fallback_required"] is True
    assert payload["current_boundary"]["missing_helpers_can_halt_block_production"] is False
    assert payload["claim_boundaries"]["production_helper_execution"] is False
