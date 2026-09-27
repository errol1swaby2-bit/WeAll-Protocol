from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"
TEMP_WORKFLOW = ".github/workflows/ci-p2-derivative-refresh.yml"
TEMP_SCRIPT = ".github/ci-p2-derivative-refresh.py"
BRANCH = "p2-complete-remediation-20260927"


def run(*args: str, cwd: Path = PROTO, env: dict[str, str] | None = None) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=merged, check=True)


def main() -> None:
    # Remove the temporary repair machinery before regeneration so the v2
    # source-tree fingerprint is bound to the final repository tree, not to
    # this one-shot workflow.
    run("git", "rm", TEMP_WORKFLOW, TEMP_SCRIPT, cwd=ROOT)

    changed_tests = [
        "tests/test_transfer_tip_contract.py",
        "tests/test_pb001bm_validator_authority_fail_closed.py",
    ]
    run("ruff", "format", "--check", *changed_tests)
    run("ruff", "check", *changed_tests)
    run(sys.executable, "-m", "tooling.canon_lint")

    # Rebuild the deterministic v2 derivatives that include source coverage
    # and the source-tree digest, then immediately prove regeneration is stable.
    run(sys.executable, "scripts/compile_v2_spec.py", env={"PYTHONPATH": "src"})
    run(
        sys.executable,
        "scripts/compile_v2_spec.py",
        "--check",
        env={"PYTHONPATH": "src"},
    )

    # Re-run the exact freshness/readiness surfaces used by standard CI.
    run(sys.executable, "scripts/check_generated.py")
    run(sys.executable, "scripts/check_v2_spec_clean_checkout.py")
    run(
        sys.executable,
        "scripts/check_v15_public_readiness_artifacts.py",
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    run(sys.executable, "scripts/check_public_claim_freshness.py")
    run(sys.executable, "scripts/gen_current_verified_claims.py", "--check")

    # Prove the two closures that caused this source-fingerprint refresh.
    run(
        "pytest",
        "-q",
        "tests/test_transfer_tip_contract.py::test_p2_econ004_content_tip_payload_passes_strict_canonical_admission",
        "tests/test_pb001bm_validator_authority_fail_closed.py::test_p2_sync002_state_sync_rejects_non_string_validator_member_before_normalization",
    )
    run("pytest", "-q", *changed_tests)

    # Do not publish refreshed evidence unless the complete backend suite is
    # still green on the resulting final tree.
    run("pytest", "-q")
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

    # Fail rather than manufacture a no-op closure commit.
    staged = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=ROOT,
        check=False,
    )
    if staged.returncode == 0:
        raise SystemExit("no derivative refresh changes were produced")
    if staged.returncode != 1:
        raise SystemExit(f"git diff --cached --quiet failed: {staged.returncode}")

    run(
        "git",
        "commit",
        "-m",
        "Refresh v2 derivatives after P2 proof closures",
        cwd=ROOT,
    )
    run("git", "push", "origin", f"HEAD:{BRANCH}", cwd=ROOT)


if __name__ == "__main__":
    main()
