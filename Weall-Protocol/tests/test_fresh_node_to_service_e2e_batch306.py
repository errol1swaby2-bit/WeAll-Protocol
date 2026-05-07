from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fresh_node_to_service_e2e.sh"
QUICKSTART = ROOT / "docs" / "NEW_NODE_OPERATOR_QUICKSTART.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_fresh_node_to_service_script_exists_and_models_full_path_batch306() -> None:
    text = read(SCRIPT)
    assert "WEALL_FRESH_SERVICE_E2E_EXECUTE" in text
    assert "boot_onboarding_node.sh" in text
    assert "boot_node_operator.sh" in text
    assert "demo_native_async_tier1_e2e.sh" in text
    assert "devnet_request_live.sh" in text
    assert "ACCOUNT_DEVICE_REGISTER" in text
    assert "ROLE_NODE_OPERATOR_ENROLL" in text
    assert "NODE_OPERATOR_STORAGE_OPT_IN" in text
    assert "NODE_OPERATOR_VALIDATOR_OPT_IN" in text
    assert "storage_probe_runner_check.py" in text
    assert "validator_readiness_check.py" in text
    assert "production-service.example.env" in text
    assert "WEALL_NODE_PRIVKEY_FILE" in text
    assert "WEALL_NODE_PRIVKEY=<account_secret>" not in text
    assert "ROLE_NODE_OPERATOR_ACTIVATE" not in text
    assert "bootstrap grant" not in text.lower()


def test_fresh_node_to_service_script_is_shell_valid_batch306() -> None:
    subprocess.run(["bash", "-n", str(SCRIPT)], cwd=str(ROOT), check=True)


def test_fresh_node_to_service_quickstart_mentions_harness_without_overpromising_batch306() -> None:
    text = read(QUICKSTART)
    assert "./scripts/fresh_node_to_service_e2e.sh" in text
    assert "WEALL_FRESH_SERVICE_E2E_EXECUTE=1" in text
    assert "does not bypass system verification" in text
    assert "capacity-probe verification" in text
    assert "validator-readiness verification" in text
    assert "WEALL_NODE_PRIVKEY=<account_secret>" not in text


def test_fresh_node_to_service_dry_run_wires_local_probe_and_readiness_tools_batch306() -> None:
    text = read(SCRIPT)
    assert "dry-run only" in text
    assert "run_local_storage_probe" in text
    assert "run_local_validator_readiness" in text
    assert "storage probe local verification OK" in text
    assert "validator readiness local verification OK" in text
    assert "storage-verify.json" in text
    assert "validator-readiness-verify.json" in text
    assert "production-service.example.env" in text
    assert "operator-status reports active responsibilities" in text

