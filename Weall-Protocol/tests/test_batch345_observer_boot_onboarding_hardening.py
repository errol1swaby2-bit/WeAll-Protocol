from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "scripts" / "build_external_observer_bundle.py"
VERIFY = ROOT / "scripts" / "verify_node_operator_onboarding_bundle.py"
LIVE_GATE = ROOT / "scripts" / "external_observer_live_gate.sh"
REHEARSAL = ROOT / "scripts" / "rehearse_external_observer_two_machine.sh"
SECRET_LIB = ROOT / "scripts" / "lib" / "observer_secret_boundary.sh"


def _write_manifest(path: Path) -> Path:
    manifest = {
        "authority": {"expected_profile": "production"},
        "authority_snapshot_version": 1,
        "chain_id": "weall-prod-batch345",
        "genesis_hash": "1" * 64,
        "genesis_state_root": "2" * 64,
        "mode": "prod",
        "profile": "production_service",
        "protocol_profile_hash": "3" * 64,
        "schema_version": "1",
        "trusted_authority_pubkeys": ["b" * 64],
        "tx_index_hash": "4" * 64,
        "version": 1,
    }
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return path


def _build_bundle(tmp_path: Path, *, genesis_api: str = "https://genesis.example.test") -> tuple[Path, Path]:
    manifest = _write_manifest(tmp_path / "manifest.json")
    bundle = tmp_path / "observer-bundle.json"
    result = subprocess.run(
        [
            sys.executable,
            str(BUILD),
            "--manifest",
            str(manifest),
            "--genesis-api-base",
            genesis_api,
            "--authority-url",
            "https://authority.example.test",
            "--out",
            str(bundle),
            "--generated-at-ms",
            "1900000000000",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return manifest, bundle


def test_observer_bundle_rejects_unsafe_runtime_flags_batch345(tmp_path: Path) -> None:
    manifest, bundle = _build_bundle(tmp_path)
    data = json.loads(bundle.read_text(encoding="utf-8"))
    data["observer"].update(
        {
            "observer_mode_required": False,
            "validator_signing_enabled": True,
            "bft_enabled": True,
            "helper_authority_enabled": True,
            "block_loop_autostart": True,
            "service_roles": ["validator"],
            "allowed_onboarding_transactions": ["ACCOUNT_REGISTER", "VALIDATOR_REGISTER"],
        }
    )
    bundle.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(manifest), "--json"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode != 0
    report = json.loads(result.stdout)
    issues = set(report["issues"])
    assert "observer_mode_required_must_be_true" in issues
    assert "observer_validator_signing_must_be_false" in issues
    assert "observer_bft_must_be_false" in issues
    assert "observer_helper_authority_must_be_false" in issues
    assert "observer_block_loop_autostart_must_be_false" in issues
    assert "observer_service_roles_must_be_empty" in issues
    assert any(issue.startswith("observer_allowed_onboarding_transactions_unsafe:") for issue in issues)


def test_observer_bundle_emit_shell_env_forces_safe_flags_batch345(tmp_path: Path) -> None:
    manifest, bundle = _build_bundle(tmp_path)

    result = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(manifest), "--emit-shell-env"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    out = result.stdout
    assert "export WEALL_SERVICE_ROLES=''" in out
    assert "export WEALL_OBSERVER_MODE=1" in out
    assert "export WEALL_VALIDATOR_SIGNING_ENABLED=0" in out
    assert "export WEALL_BFT_ENABLED=0" in out
    assert "export WEALL_HELPER_MODE_ENABLED=0" in out
    assert "export WEALL_BLOCK_LOOP_AUTOSTART=0" in out


def test_external_observer_live_gate_rejects_ipv6_loopback_before_network_batch345(tmp_path: Path) -> None:
    manifest, bundle = _build_bundle(tmp_path)
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("WEALL_"):
            env.pop(key)
    env.update(
        {
            "WEALL_CHAIN_MANIFEST_PATH": str(manifest),
            "WEALL_GENESIS_API_BASE": "http://[::1]:8000",
        }
    )

    result = subprocess.run(
        ["bash", str(LIVE_GATE), str(bundle)],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert result.returncode != 0
    assert "external observer live gate requires a remote non-local genesis API base" in result.stdout


def test_observer_secret_boundary_is_shared_by_all_observer_scripts_batch345() -> None:
    assert SECRET_LIB.exists()
    lib = SECRET_LIB.read_text(encoding="utf-8")
    for needle in (
        "WEALL_AUTHORITY_SIGNER_PRIVKEY_FILE",
        "WEALL_AUTHORITY_PRIVKEY_FILE",
        "WEALL_VALIDATOR_PRIVKEY_FILE",
        "WEALL_NODE_PRIVKEY_FILE",
        "WEALL_DNS_API_TOKEN",
        "WEALL_OAUTH_CLIENT_SECRET",
        "WEALL_KYC_API_KEY",
        "WEALL_CAPTCHA_SECRET",
        "WEALL_SM\"\"TP_PASSWORD_FILE",
    ):
        assert needle in lib

    for script_name in (
        "external_observer_live_gate.sh",
        "external_observer_onboarding_smoke.sh",
        "rehearse_external_observer_two_machine.sh",
        "local_observer_readiness_gate.sh",
    ):
        script = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
        assert "observer_secret_boundary.sh" in script
        assert "weall_check_observer_secret_boundary" in script


def test_boot_onboarding_requires_preflight_or_public_bundle_batch345() -> None:
    script = (ROOT / "scripts" / "boot_onboarding_node.sh").read_text(encoding="utf-8")
    assert "WEALL_OBSERVER_PREFLIGHT_ALREADY_PASSED" in script
    assert "WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE" in script
    assert "external_observer_onboarding_smoke.sh" in script
    assert "set WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE or run scripts/external_observer_onboarding_smoke.sh" in script


def test_boot_node_operator_runs_prod_preflight_before_service_boot_batch345() -> None:
    script = (ROOT / "scripts" / "boot_node_operator.sh").read_text(encoding="utf-8")
    assert "prod_node_preflight.sh" in script
    assert script.index("prod_node_preflight.sh") < script.index("run_node_prod.sh")


def test_two_machine_rehearsal_is_not_documented_as_live_e2e_batch345() -> None:
    script = REHEARSAL.read_text(encoding="utf-8")
    assert "connectivity/preflight only" in script
    assert "does not submit signed onboarding transactions" in script
    assert "external_observer_live_gate.sh" in script


def test_external_observer_final_authority_absence_checks_operator_status_batch345() -> None:
    script = LIVE_GATE.read_text(encoding="utf-8")
    assert "/v1/accounts/" in script
    assert "/operator-status?node_pubkey=" in script
    assert "observer_account_unexpected_operator_authority" in script
    assert "observer_account_unexpected_authority" in script
