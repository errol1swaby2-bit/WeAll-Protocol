from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def _read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def test_reviewer_workflow_is_tracked_and_runs_the_gate() -> None:
    workflow = _read(".github/workflows/reviewer-readiness.yml")
    assert "name: Reviewer Readiness" in workflow
    assert "Run reviewer readiness gate" in workflow
    assert "bash scripts/reviewer_production_readiness_gate.sh" in workflow
    assert "requirements-dev.lock" in workflow
    assert "npm ci" in workflow


def test_block_proof_gate_no_longer_overclaims_production_validator_bft() -> None:
    script = _read("Weall-Protocol/scripts/production_block_production_rehearsal_gate.py")
    docs = _read("Weall-Protocol/docs/BLOCK_PRODUCTION_PROOF_GATE.md")
    gap = _read("Weall-Protocol/docs/PRODUCTION_ORIENTED_REHEARSAL_GAP_AUDIT.md")

    assert "local block-production evidence gate" in script
    assert "OK: local block-production proof" in script
    assert "production-profile" in script
    assert "validator readiness" in script
    assert "public multi-validator BFT readiness" in script
    assert "production-profile validator/BFT readiness is not claimed" in docs
    assert "public multi-validator BFT not claimed" in docs
    assert "block production proof truth boundary" in gap
    assert "OK: local production-profile block proof" not in script


def test_block_proof_gate_refuses_prod_mode_to_prevent_false_claims() -> None:
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(ROOT / "src"),
        "WEALL_MODE": "prod",
        "WEALL_CHAIN_ID": "weall-prod",
        "WEALL_CHAIN_MANIFEST_PATH": str(ROOT / "configs/chains/weall-genesis.json"),
        "WEALL_REQUIRE_CHAIN_MANIFEST": "1",
    })
    proc = subprocess.run(
        [sys.executable, "scripts/production_block_production_rehearsal_gate.py"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert proc.returncode != 0
    assert "intentionally local-only" in proc.stdout
    assert "production-profile validator/BFT proof" in proc.stdout


def test_reviewer_gate_includes_local_observer_preconditions() -> None:
    gate = _read("Weall-Protocol/scripts/reviewer_production_readiness_gate.sh")
    assert "WEALL_REVIEWER_INCLUDE_LOCAL_OBSERVER_GATES" in gate
    assert "external_observer_authority_lock_gate.sh" in gate
    assert "local_observer_readiness_gate.sh" in gate
    assert "first_external_observer_reproducibility_gate.sh" in gate
    assert "production_block_production_rehearsal_gate.py" in gate
    assert "test_reviewer_truth_and_observer_reproducibility.py" in gate
    assert "production validator/BFT readiness" in gate


def test_first_external_observer_reproducibility_gate_has_truth_boundary() -> None:
    script = _read("Weall-Protocol/scripts/first_external_observer_reproducibility_gate.sh")
    assert "local_observer_readiness_gate.sh" in script
    assert "external_observer_authority_lock_gate.sh" in script
    assert "rehearse_external_observer_two_machine.sh" in script
    assert "rehearse_external_observer_signed_onboarding.sh" in script
    assert "WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT" in script
    assert "WEALL_RUN_SIGNED_OBSERVER_ONBOARDING" in script
    assert "Signed onboarding passing is required before claiming first trusted external observer readiness" in script
    assert "None of these gates prove public multi-validator BFT" in script


def test_block_production_readiness_uses_env_mode_when_state_meta_lacks_mode() -> None:
    consensus_routes = _read("Weall-Protocol/src/weall/api/routes_public_parts/consensus.py")
    assert 'os.environ.get("WEALL_MODE")' in consensus_routes


def test_public_ingress_authority_boundaries_are_source_tracked() -> None:
    tx_admission = _read("Weall-Protocol/src/weall/runtime/tx_admission.py")
    domain_dispatch = _read("Weall-Protocol/src/weall/runtime/domain_dispatch.py")
    consensus_routes = _read("Weall-Protocol/src/weall/api/routes_public_parts/consensus.py")

    assert "system_tx_forbidden" in tx_admission
    assert "system_only_tx_not_allowed_in_public_ingress" in tx_admission
    assert "system_enforced" in domain_dispatch
    assert "system_signer_required" in domain_dispatch
    assert "system_tx_forbidden" in consensus_routes
    assert "signature is required for public attestation submission" in consensus_routes
    assert "verify_tx_signature" in consensus_routes
