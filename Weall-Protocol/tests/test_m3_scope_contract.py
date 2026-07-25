from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "Weall-Protocol"
TRACE_PATH = BACKEND_ROOT / "docs/production_readiness/M3_REQUIREMENT_TRACEABILITY.json"
CROSSWALK_PATH = BACKEND_ROOT / "docs/production_readiness/M3_SCOPE_CROSSWALK.json"
TRUTH_PATH = BACKEND_ROOT / "docs/production_readiness/M3_TRUTH_BOUNDARIES.md"
CLOSURE_PATH = BACKEND_ROOT / "docs/production_readiness/M3_CLOSURE_PROCESS.md"
E2E_PATH = REPO_ROOT / "web/tests/e2e/m3_civic_governance_real_stack.spec.ts"
PACKAGE_PATH = REPO_ROOT / "web/package.json"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_m3_traceability_checker_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_m3_requirement_traceability.py"],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "OK: M3 traceability validated" in result.stdout


def test_m3_traceability_records_protocol_corrections_as_evidence_gated() -> None:
    trace = _json(TRACE_PATH)
    rows = {
        str(row["id"]): row
        for row in trace["requirements"]  # type: ignore[index]
    }
    for row_id in (
        "M3-P0-01",
        "M3-P0-02",
        "M3-P0-03",
        "M3-P0-04",
        "M3-P0-05",
        "M3-P1-09",
    ):
        assert rows[row_id]["status"] == "implemented_requires_integrated_evidence"

    crosswalk = _json(CROSSWALK_PATH)
    assert crosswalk["blocking_protocol_gaps"] == []
    corrections = {
        str(row["mechanism_id"])
        for row in crosswalk["implemented_protocol_corrections"]  # type: ignore[index]
    }
    assert corrections == {"M-050", "M-051"}


def test_m3_docs_preserve_bounded_claim_language() -> None:
    truth = TRUTH_PATH.read_text(encoding="utf-8")
    closure = CLOSURE_PATH.read_text(encoding="utf-8")
    combined = f"{truth}\n{closure}".lower()

    for required in (
        "implementation-freeze commit",
        "evidence-only direct child",
        "first admitted final ballot",
        "versioned electorate round",
        "active round denominator never drifts in place",
        "expires with an explicit no-decision receipt",
        "validators are not political principals",
        "public beta",
        "mainnet",
        "emergency governance",
        "r-m1",
    ):
        assert required.lower() in combined

    assert "m3 is closed" not in combined
    assert "production constitutional governance is complete" not in combined


def test_m3_real_stack_journey_is_non_skippable_and_manifest_bound() -> None:
    source = E2E_PATH.read_text(encoding="utf-8")
    package = _json(PACKAGE_PATH)
    scripts = package["scripts"]  # type: ignore[index]

    assert scripts["test:m3-civic-governance-real-stack"] == (
        "playwright test tests/e2e/m3_civic_governance_real_stack.spec.ts"
    )

    for marker in (
        "signed public content",
        "canonical group membership",
        "public report and independent review",
        "appeal and final receipt",
        "versioned electorate round",
        "first admitted final ballot",
        "block-height tally and finalization",
        "WEALL_M3_ACTOR_MANIFEST",
        "storageState",
        "transaction_transcript",
        "negative signed attempts fail closed",
        "submitSignedTx",
        "identity_choice_maps_exposed",
    ):
        assert marker in source

    forbidden = (
        "test.skip",
        "test.fixme",
        "load-demo-tester-session",
        "apply_governance(",
        "apply_dispute(",
        "apply_content(",
        "apply_groups(",
        "M3_CLOSURE_NOT_IMPLEMENTED",
        "recovery_file?:",
    )
    for marker in forbidden:
        assert marker not in source


def test_m3_complete_closure_runner_is_fail_closed_and_complete() -> None:
    runner = (REPO_ROOT / "scripts/run_m3_complete_closure.sh").read_text(encoding="utf-8")
    for marker in (
        "check_m3_dependencies.py",
        "check_m3_requirement_traceability.py",
        "gen_governance_execution_vectors_v1_5.py --check",
        "check_v15_public_readiness_artifacts.py",
        "compile_v2_spec.py --check",
        "run_m3_clean_checkout_reproduction.sh",
        "test_m3_closure_regressions.py",
        "test_m3_closure_integrity.py",
        "test_priority1_replay_schedule_consistency.py",
        "test_helper_multinode_divergence_guards.py",
        "npm run typecheck",
        "npm run build",
        "run_m3_civic_real_stack_e2e.sh",
        "run_m3_restart_replay_gate.sh",
        "run_m3_two_node_state_root_gate.sh",
        "run_m3_observer_catchup_gate.sh",
        "run_m3_privacy_scan.sh",
        "M3_IMPLEMENTATION_FREEZE_COMMIT",
        "--evidence-only",
        "gen_m3_closure_manifest.py",
    ):
        assert marker in runner

    assert "set -uo pipefail" in runner
    assert "|| true" not in runner


def test_m3_evidence_only_checker_binds_direct_child_and_all_gates() -> None:
    checker = (REPO_ROOT / "scripts/check_m3_evidence_only_commit.py").read_text(encoding="utf-8")
    contract = (REPO_ROOT / "scripts/m3_evidence_contract.py").read_text(encoding="utf-8")
    wrapper = (REPO_ROOT / "scripts/check_m3_evidence_only_commit.sh").read_text(encoding="utf-8")
    for marker in (
        "m3_evidence_commit_not_direct_child",
        "m3_evidence_non_evidence_path",
        "m3_evidence_manifest_path_set_mismatch",
        "m3_evidence_gate_set_mismatch",
        "all_gates_passed",
        "schema_version",
    ):
        assert marker in checker
    for marker in (
        "M3_ACTOR_MANIFEST.json",
        "transaction-transcript.json",
        "restart-replay/final-state.json",
        "two-node/final-state.json",
        "observer/final-state.json",
        "private-material-scan.json",
    ):
        assert marker in contract
    assert "--cached" in wrapper
    assert "M3_IMPLEMENTATION_FREEZE_COMMIT" in wrapper
