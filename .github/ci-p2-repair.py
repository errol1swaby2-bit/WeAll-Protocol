from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"


def run(*args: str, cwd: Path = PROTO, env: dict[str, str] | None = None) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=merged, check=True)


def patch_tests() -> None:
    dispute_path = PROTO / "tests/test_constitutional_procedure_clock.py"
    text = dispute_path.read_text(encoding="utf-8")
    old = '        "d1": {"dispute_id": "d1", "stage": "review", "appeal_window_blocks": 3}\n'
    new = (
        '        "d1": {\n'
        '            "dispute_id": "d1",\n'
        '            "stage": "review",\n'
        '            "appeal_window_blocks": 3,\n'
        '            "target_type": "account",\n'
        '            "target_id": "alice",\n'
        '        }\n'
    )
    if new not in text:
        if old not in text:
            raise SystemExit("constitutional dispute fixture anchor missing")
        text = text.replace(old, new, 1)
    dispute_path.write_text(text, encoding="utf-8")

    compiler_path = PROTO / "tests/test_v2_spec_compiler.py"
    compiler = compiler_path.read_text(encoding="utf-8")
    old_count = '    assert runtime["count"] == 1118\n'
    new_count = '    assert runtime["count"] == 1122\n'
    if new_count not in compiler:
        if old_count not in compiler:
            raise SystemExit("runtime inventory count assertion anchor missing")
        compiler = compiler.replace(old_count, new_count, 1)
    compiler_path.write_text(compiler, encoding="utf-8")


def main() -> None:
    run(
        "git",
        "rm",
        ".github/workflows/ci-p2-repair.yml",
        ".github/ci-p2-repair.py",
        cwd=ROOT,
    )
    patch_tests()

    run(
        "ruff",
        "format",
        "tests/test_constitutional_procedure_clock.py",
        "tests/test_v2_spec_compiler.py",
    )
    run(
        "ruff",
        "format",
        "--check",
        "tests/test_constitutional_procedure_clock.py",
        "tests/test_v2_spec_compiler.py",
    )
    run(
        "ruff",
        "check",
        "tests/test_constitutional_procedure_clock.py",
        "tests/test_v2_spec_compiler.py",
    )

    proof_generators = [
        "scripts/gen_b528_b532_completion_proof_v1_5.py",
        "scripts/gen_b534_b538_completion_proof_v1_5.py",
        "scripts/gen_b539_b543_production_path_proof_v1_5.py",
        "scripts/gen_b567_b571_autonomous_mechanics_proof_v1_5.py",
    ]
    for script in proof_generators:
        run(sys.executable, script)
    for script in proof_generators:
        run(sys.executable, script, "--check")

    run(sys.executable, "scripts/gen_failure_code_registry_v1_5.py")
    run(sys.executable, "scripts/gen_release_evidence_manifest_v1_5.py", env={"PYTHONPATH": "src"})
    run(
        sys.executable,
        "scripts/gen_public_beta_blocker_report_v1_5.py",
        env={"PYTHONPATH": "src:scripts"},
    )
    run(sys.executable, "scripts/gen_current_verified_claims.py")

    run(sys.executable, "scripts/gen_failure_code_registry_v1_5.py", "--check")
    run(
        sys.executable,
        "scripts/gen_release_evidence_manifest_v1_5.py",
        "--check",
        env={"PYTHONPATH": "src"},
    )
    run(
        sys.executable,
        "scripts/gen_public_beta_blocker_report_v1_5.py",
        "--check",
        env={"PYTHONPATH": "src:scripts"},
    )
    run(sys.executable, "scripts/gen_current_verified_claims.py", "--check")

    run(sys.executable, "scripts/compile_v2_spec.py", env={"PYTHONPATH": "src"})
    run(sys.executable, "scripts/compile_v2_spec.py", "--check", env={"PYTHONPATH": "src"})
    run(
        sys.executable,
        "scripts/check_v15_public_readiness_artifacts.py",
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    run(sys.executable, "scripts/check_public_claim_freshness.py")
    run(sys.executable, "scripts/gen_current_verified_claims.py", "--check")

    run(
        "pytest",
        "-q",
        "tests/test_autonomous_validator_ipfs_anti_sybil_economics_read_models.py::test_claim_boundaries_and_artifact_freshness",
        "tests/test_constitutional_procedure_clock.py::test_dispute_verdict_opens_appeal_window_and_engine_finalizes_after_deadline",
        "tests/test_full_node_db_api_dispute_storage_coverage.py::test_b534_freshness_check_is_deterministic_and_live_verification_is_explicit",
        "tests/test_production_bft_block_replay_api_storage_claim_boundaries.py::test_generated_artifact_is_fresh",
        "tests/test_v2_spec_compiler.py::test_exact_state_contracts_are_separate_from_runtime_inventory",
        "tests/test_validator_db_lifecycle_reviewer_accountability_storage_coverage.py::test_b528_freshness_check_is_deterministic_and_live_verification_is_explicit",
    )
    run("git", "diff", "--check", cwd=ROOT)

    run("git", "config", "user.name", "github-actions[bot]", cwd=ROOT)
    run(
        "git",
        "config",
        "user.email",
        "41898282+github-actions[bot]@users.noreply.github.com",
        cwd=ROOT,
    )
    run("git", "add", "-A", cwd=ROOT)
    run("git", "diff", "--cached", "--check", cwd=ROOT)
    run("git", "commit", "-m", "Repair full-suite P2 closure fallout", cwd=ROOT)
    run("git", "push", "origin", "HEAD:p2-complete-remediation-20260927", cwd=ROOT)


if __name__ == "__main__":
    main()
