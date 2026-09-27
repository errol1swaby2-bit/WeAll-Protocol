from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"
BRANCH = "p2-storage-closure-20260927"
OLD_SCRIPT = ROOT / ".github/ci-p2-storage-closure.py"
TEMP_PATHS = (
    ".github/ci-p2-storage-closure.py",
    ".github/workflows/ci-p2-storage-closure.yml",
    ".github/ci-p2-storage-closure-v2.py",
    ".github/workflows/ci-p2-storage-closure-v2.yml",
)


def run(*args: str, cwd: Path = PROTO, env: dict[str, str] | None = None) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=merged, check=True)


def load_patch_module():
    spec = importlib.util.spec_from_file_location("p2_storage_patch", OLD_SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit("unable to load staged storage patch module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    patch = load_patch_module()

    # Remove all temporary closure machinery before changing source so every
    # generated source-tree fingerprint is bound to the intended final tree.
    run("git", "rm", *TEMP_PATHS, cwd=ROOT)

    patch.patch_schema()
    patch.patch_storage_runtime()
    patch.patch_scheduler()
    patch.patch_rehearsal()
    patch.write_tests()

    changed = [
        "src/weall/runtime/tx_schema.py",
        "src/weall/runtime/apply/storage.py",
        "src/weall/runtime/scheduler_pipeline.py",
        "scripts/rehearse_storage_operator_durability_v1_5.py",
        "tests/test_p2_storage_closure.py",
    ]
    run("ruff", "format", *changed)
    run("ruff", "check", *changed)
    run(sys.executable, "-m", "tooling.canon_lint")

    # Reproduce the three historical P2 counterexamples before refreshing any
    # reviewer-facing semantic bindings.
    run("pytest", "-q", "tests/test_p2_storage_closure.py")
    run(sys.executable, "scripts/rehearse_storage_operator_durability_v1_5.py", "--json")

    # These transaction semantics were explicitly changed by this closure.
    # Use the repository's narrow semantic-review refresh tool rather than
    # editing review digests or generated v2 artifacts by hand.
    refresh = [
        sys.executable,
        "scripts/refresh_v2_semantic_reviews.py",
        "--tx-type",
        "IPFS_PIN_CONFIRM",
        "--tx-type",
        "STORAGE_LEASE_CREATE",
        "--tx-type",
        "STORAGE_LEASE_RENEW",
        "--tx-type",
        "STORAGE_LEASE_REVOKE",
        "--tx-type",
        "STORAGE_PROOF_SUBMIT",
        "--reviewer",
        "WeAll Protocol P2 audit remediation; independent launch review deferred",
        "--review-method",
        "confirmed_audit_finding_repair_with_adversarial_regression",
    ]
    for failure in (
        "invalid_state:offer_missing_operator_id",
        "forbidden:lease_not_active",
        "forbidden:lease_expired",
        "not_found:pin_not_found",
        "invalid_state:pin_missing_cid",
        "invalid_payload:pin_cid_mismatch",
        "invalid_payload:missing_operator_id",
        "forbidden:pin_confirm_operator_not_current_target",
    ):
        refresh.extend(["--register-failure", failure])
    run(*refresh)

    # The refresh command writes all v2 derivatives. Prove they are now stable
    # and that every standard generated/readiness claim remains current.
    run(sys.executable, "scripts/compile_v2_spec.py", "--check", env={"PYTHONPATH": "src"})
    run(sys.executable, "scripts/check_generated.py")
    run(
        sys.executable,
        "scripts/check_v15_public_readiness_artifacts.py",
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    run(sys.executable, "scripts/check_public_claim_freshness.py")
    run(sys.executable, "scripts/gen_current_verified_claims.py", "--check")

    # Publication remains gated on the entire backend suite, not just focused
    # closure regressions.
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
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if staged.returncode == 0:
        raise SystemExit("storage closure produced no staged changes")
    if staged.returncode != 1:
        raise SystemExit(f"git diff --cached --quiet failed: {staged.returncode}")
    run("git", "commit", "-m", "Close P2 storage invariants", cwd=ROOT)
    run("git", "push", "origin", f"HEAD:{BRANCH}", cwd=ROOT)


if __name__ == "__main__":
    main()
