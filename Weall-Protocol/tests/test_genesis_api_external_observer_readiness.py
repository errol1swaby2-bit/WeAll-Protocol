from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def _read(path: str) -> str:
    return (OUTER / path).read_text(encoding="utf-8")


def test_genesis_observer_readiness_endpoint_is_mounted_and_truthful_batch464() -> None:
    status = _read("Weall-Protocol/src/weall/api/routes_public_parts/status.py")
    routes = _read("Weall-Protocol/src/weall/api/routes_public.py")

    assert '@router.get("/genesis/observer/readiness")' in status
    assert '@router.get("/genesis/api/readiness")' in status
    assert "def _genesis_observer_readiness_payload" in status
    assert "first_trusted_external_observer_rehearsal" in status
    assert "Remote Genesis API compatibility/readiness surface only" in status
    assert "observer_receives_validator_authority" in status
    assert "requires_genesis_or_validator_private_keys" in status
    assert "requires_external_identity_provider" in status
    assert "signed_user_tx_submit_enabled" in status
    assert "system_signer_rejected_from_public_ingress" in status
    assert "system_flag_rejected_from_public_ingress" in status
    assert "authority_is_granted_only_by_committed_protocol_state" in status
    assert "frontend_or_bundle_cannot_grant_authority" in status
    assert "chain_id" in status and "tx_index_hash" in status and "protocol_profile_hash" in status
    assert "status_router" in routes and "include_router(status_router" in routes


def test_external_observer_remote_gates_require_genesis_readiness_contract_batch464() -> None:
    two_machine = _read("Weall-Protocol/scripts/rehearse_external_observer_two_machine.sh")
    live_gate = _read("Weall-Protocol/scripts/external_observer_live_gate.sh")
    first_gate = _read("Weall-Protocol/scripts/first_external_observer_reproducibility_gate.sh")

    for script in (two_machine, live_gate):
        assert "/v1/genesis/observer/readiness" in script
        assert "remote_genesis_observer_readiness_not_ok" in script
        assert "remote_genesis_observer_readiness_stage_invalid" in script
        assert "remote_observer_readiness_validator_authority_not_false" in script
        assert "remote_observer_readiness_requires_private_keys" in script
        assert "remote_observer_readiness_requires_external_identity_provider" in script
        assert "remote_observer_readiness_signed_tx_submit_not_enabled" in script
        assert "remote_observer_readiness_system_signer_not_rejected" in script
        assert "remote_observer_readiness_system_flag_not_rejected" in script

    assert "WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT" in first_gate
    assert "WEALL_RUN_SIGNED_OBSERVER_ONBOARDING" in first_gate
    assert "Signed onboarding passing is required before claiming first trusted external observer readiness" in first_gate


def test_public_tx_submit_remains_fail_closed_for_genesis_api_batch464() -> None:
    tx_route = _read("Weall-Protocol/src/weall/api/routes_public_parts/tx.py")
    tx_admission = _read("Weall-Protocol/src/weall/runtime/tx_admission.py")
    domain_dispatch = _read("Weall-Protocol/src/weall/runtime/domain_dispatch.py")

    assert '@router.post("/tx/submit")' in tx_route
    assert "validate_tx_envelope(body)" in tx_route
    assert "_validate_public_tx_chain_id" in tx_route
    assert 'signer == "SYSTEM"' in tx_route
    assert 'body.get("system"' in tx_route
    assert "system_tx_forbidden" in tx_route
    assert "receipt_submission_forbidden" in tx_route
    assert "_http_requires_sig_by_default" in tx_route
    assert "verify_tx_signature" in tx_route
    assert "_require_registered_signer_for_user_tx" in tx_route
    assert "system_only_tx_not_allowed_in_public_ingress" in tx_admission
    assert "system_tx_forbidden" in tx_admission
    assert "system_enforced" in domain_dispatch
    assert "system_signer_required" in domain_dispatch


def test_reviewer_gate_runs_batch464_genesis_api_readiness_tests() -> None:
    gate = _read("Weall-Protocol/scripts/reviewer_production_readiness_gate.sh")
    assert "tests/test_genesis_api_external_observer_readiness.py" in gate


def test_docs_define_production_oriented_genesis_api_boundary_batch464() -> None:
    first = _read("Weall-Protocol/docs/FIRST_EXTERNAL_OBSERVER_TEST.md")
    trusted = _read("Weall-Protocol/docs/TRUSTED_EXTERNAL_OBSERVER_TESTER_RUNBOOK.md")
    rehearsal = _read("Weall-Protocol/docs/EXTERNAL_OBSERVER_NODE_REHEARSAL.md")
    known = _read("Weall-Protocol/docs/KNOWN_LIMITATIONS.md")

    for doc in (first, trusted, rehearsal):
        assert "/v1/genesis/observer/readiness" in doc
        assert "remote Genesis observer readiness" in doc or "Genesis observer readiness" in doc
        assert "WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1" in doc
        assert "WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1" in doc

    assert "Production-oriented Genesis API" in known
    assert "not a public mainnet Genesis API" in known


def test_first_external_observer_gate_still_passes_local_scope_batch464() -> None:
    proc = subprocess.run(
        ["bash", "scripts/first_external_observer_reproducibility_gate.sh"],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "HOME": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert "local observer readiness" in proc.stdout
    assert "observer authority lock" in proc.stdout
    assert "remote preflight skipped" in proc.stdout
    assert "signed onboarding skipped" in proc.stdout
    assert "Signed onboarding passing is required before claiming first trusted external observer readiness" in proc.stdout
